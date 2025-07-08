package live

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/janus-project/janus/pkg/types"
)

// streamingCorrelatorImpl implements the StreamingCorrelator interface
type streamingCorrelatorImpl struct {
	config      StreamingCorrelatorConfig
	running     bool
	mu          sync.RWMutex
	
	// Flow tracking
	flows       map[types.FlowKey]*liveFlow
	flowMu      sync.RWMutex
	evictionMu  sync.Mutex
	
	// Channels
	correlations chan LiveCorrelation
	stopChan     chan struct{}
	
	// Statistics
	stats   CorrelationStats
	statsMu sync.Mutex
	
	// Workers
	workerCount int
	workers     []chan LivePacket
}

// liveFlow represents a flow being tracked in real-time
type liveFlow struct {
	key         types.FlowKey
	packets     []LivePacket
	points      map[string]bool
	firstSeen   time.Time
	lastSeen    time.Time
	mu          sync.Mutex
}

// NewStreamingCorrelator creates a new streaming correlator
func NewStreamingCorrelator(config StreamingCorrelatorConfig) StreamingCorrelator {
	// Set defaults
	if config.WindowSize == 0 {
		config.WindowSize = time.Second * 5
	}
	if config.MaxFlows == 0 {
		config.MaxFlows = 1000
	}
	if config.MinConfidence == 0 {
		config.MinConfidence = 0.7
	}
	if config.WorkerCount == 0 {
		config.WorkerCount = 4
	}
	
	sc := &streamingCorrelatorImpl{
		config:       config,
		flows:        make(map[types.FlowKey]*liveFlow),
		correlations: make(chan LiveCorrelation, 1000),
		stopChan:     make(chan struct{}),
		workerCount:  config.WorkerCount,
		workers:      make([]chan LivePacket, config.WorkerCount),
	}
	
	// Initialize worker channels
	for i := 0; i < config.WorkerCount; i++ {
		sc.workers[i] = make(chan LivePacket, 100)
	}
	
	return sc
}

// Start begins the streaming correlator
func (sc *streamingCorrelatorImpl) Start(ctx context.Context) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	
	if sc.running {
		return fmt.Errorf("correlator already running")
	}
	
	sc.running = true
	
	// Start worker goroutines
	for i := 0; i < sc.workerCount; i++ {
		go sc.worker(i)
	}
	
	// Start cleanup goroutine for expired flows
	go sc.cleanupWorker()
	
	return nil
}

// Stop halts the streaming correlator
func (sc *streamingCorrelatorImpl) Stop() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	
	if !sc.running {
		return nil
	}
	
	// Signal workers to stop
	close(sc.stopChan)
	
	// Close worker channels
	for _, worker := range sc.workers {
		close(worker)
	}
	
	sc.running = false
	
	return nil
}

// Close releases resources
func (sc *streamingCorrelatorImpl) Close() error {
	return sc.Stop()
}

// IsRunning returns whether the correlator is active
func (sc *streamingCorrelatorImpl) IsRunning() bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.running
}

// ProcessPacket adds a packet for correlation processing
func (sc *streamingCorrelatorImpl) ProcessPacket(packet LivePacket) error {
	sc.mu.RLock()
	running := sc.running
	sc.mu.RUnlock()
	
	if !running {
		return fmt.Errorf("correlator not running")
	}
	
	// Hash packet to worker based on flow key
	workerIndex := sc.hashFlowKey(packet.FlowKey) % sc.workerCount
	
	// Send to worker (non-blocking)
	select {
	case sc.workers[workerIndex] <- packet:
		sc.updateStats(func(stats *CorrelationStats) {
			stats.PacketsProcessed++
		})
		return nil
	default:
		return fmt.Errorf("worker queue full")
	}
}

// worker processes packets assigned to it
func (sc *streamingCorrelatorImpl) worker(id int) {
	for packet := range sc.workers[id] {
		sc.processPacketInternal(packet)
	}
}

// processPacketInternal handles packet correlation logic
func (sc *streamingCorrelatorImpl) processPacketInternal(packet LivePacket) {
	flowKey := packet.FlowKey
	
	sc.flowMu.Lock()
	flow, exists := sc.flows[flowKey]
	if !exists {
		// Check if we need to evict flows first
		if len(sc.flows) >= sc.config.MaxFlows {
			sc.evictOldestFlow()
		}
		
		flow = &liveFlow{
			key:       flowKey,
			packets:   make([]LivePacket, 0),
			points:    make(map[string]bool),
			firstSeen: packet.Timestamp,
			lastSeen:  packet.Timestamp,
		}
		sc.flows[flowKey] = flow
		
		sc.updateStats(func(stats *CorrelationStats) {
			stats.ActiveFlows++
		})
	}
	sc.flowMu.Unlock()
	
	// Add packet to flow
	flow.mu.Lock()
	flow.packets = append(flow.packets, packet)
	flow.points[packet.PointID] = true
	flow.lastSeen = packet.Timestamp
	
	// Check for correlation if we have packets from multiple points
	if len(flow.points) > 1 {
		correlation := sc.checkCorrelation(flow)
		if correlation != nil {
			flow.mu.Unlock()
			
			// Send correlation (non-blocking)
			select {
			case sc.correlations <- *correlation:
				sc.updateStats(func(stats *CorrelationStats) {
					stats.CorrelationsFound++
				})
			default:
				// Correlation channel full
			}
		} else {
			flow.mu.Unlock()
		}
	} else {
		flow.mu.Unlock()
	}
}

// checkCorrelation examines a flow for correlation patterns
func (sc *streamingCorrelatorImpl) checkCorrelation(flow *liveFlow) *LiveCorrelation {
	if len(flow.packets) < 2 {
		return nil
	}
	
	// Simple correlation based on configured methods
	confidence := 0.0
	methods := []string{}
	
	// Check IP ID correlation
	if sc.hasMethod("ipid") {
		if ipidConfidence := sc.checkIPIDCorrelation(flow.packets); ipidConfidence > 0 {
			confidence += ipidConfidence
			methods = append(methods, "ipid")
		}
	}
	
	// Check payload hash correlation
	if sc.hasMethod("payload_hash") {
		if payloadConfidence := sc.checkPayloadCorrelation(flow.packets); payloadConfidence > 0 {
			confidence += payloadConfidence
			methods = append(methods, "payload_hash")
		}
	}
	
	// Check TCP sequence correlation
	if sc.hasMethod("tcp_sequence") {
		if tcpConfidence := sc.checkTCPCorrelation(flow.packets); tcpConfidence > 0 {
			confidence += tcpConfidence
			methods = append(methods, "tcp_sequence")
		}
	}
	
	// Average confidence across methods
	if len(methods) > 0 {
		confidence = confidence / float64(len(methods))
	}
	
	if confidence < sc.config.MinConfidence {
		return nil
	}
	
	// Create correlation result
	var points []string
	for point := range flow.points {
		points = append(points, point)
	}
	
	latency := flow.lastSeen.Sub(flow.firstSeen)
	
	return &LiveCorrelation{
		FlowKey:     flow.key,
		Points:      points,
		Confidence:  confidence,
		Latency:     latency,
		Methods:     methods,
		Timestamp:   time.Now(),
		PacketCount: len(flow.packets),
	}
}

// hasMethod checks if a correlation method is enabled
func (sc *streamingCorrelatorImpl) hasMethod(method string) bool {
	for _, m := range sc.config.CorrelationMethods {
		if m == method {
			return true
		}
	}
	return true // Default to enabled if no methods specified
}

// checkIPIDCorrelation looks for IP ID matches
func (sc *streamingCorrelatorImpl) checkIPIDCorrelation(packets []LivePacket) float64 {
	ipidCounts := make(map[uint16]int)
	
	for _, packet := range packets {
		if packet.Data.IPID != 0 {
			ipidCounts[packet.Data.IPID]++
		}
	}
	
	// Look for common IP IDs
	for _, count := range ipidCounts {
		if count > 1 {
			return 0.8 // High confidence for IP ID match
		}
	}
	
	return 0.0
}

// checkPayloadCorrelation looks for payload hash matches
func (sc *streamingCorrelatorImpl) checkPayloadCorrelation(packets []LivePacket) float64 {
	hashCounts := make(map[string]int)
	
	for _, packet := range packets {
		if packet.Data.PayloadHash != "" {
			hashCounts[packet.Data.PayloadHash]++
		}
	}
	
	// Look for common payload hashes
	for _, count := range hashCounts {
		if count > 1 {
			return 0.9 // Very high confidence for payload match
		}
	}
	
	return 0.0
}

// checkTCPCorrelation looks for TCP sequence patterns
func (sc *streamingCorrelatorImpl) checkTCPCorrelation(packets []LivePacket) float64 {
	seqCounts := make(map[uint32]int)
	
	for _, packet := range packets {
		if packet.Data.Protocol == "tcp" && packet.Data.TCPSeq != 0 {
			seqCounts[packet.Data.TCPSeq]++
		}
	}
	
	// Look for common TCP sequences
	for _, count := range seqCounts {
		if count > 1 {
			return 0.7 // Good confidence for TCP sequence match
		}
	}
	
	return 0.0
}

// evictOldestFlow removes the oldest flow to make space
func (sc *streamingCorrelatorImpl) evictOldestFlow() {
	var oldestKey types.FlowKey
	var oldestTime time.Time
	
	for key, flow := range sc.flows {
		flow.mu.Lock()
		if oldestTime.IsZero() || flow.firstSeen.Before(oldestTime) {
			oldestTime = flow.firstSeen
			oldestKey = key
		}
		flow.mu.Unlock()
	}
	
	if !oldestTime.IsZero() {
		delete(sc.flows, oldestKey)
		sc.updateStats(func(stats *CorrelationStats) {
			stats.ActiveFlows--
			stats.EvictedFlows++
		})
	}
}

// cleanupWorker periodically removes expired flows
func (sc *streamingCorrelatorImpl) cleanupWorker() {
	ticker := time.NewTicker(sc.config.WindowSize / 2)
	defer ticker.Stop()
	
	for {
		select {
		case <-sc.stopChan:
			return
		case <-ticker.C:
			sc.cleanupExpiredFlows()
		}
	}
}

// cleanupExpiredFlows removes flows older than the window size
func (sc *streamingCorrelatorImpl) cleanupExpiredFlows() {
	now := time.Now()
	expired := make([]types.FlowKey, 0)
	
	sc.flowMu.RLock()
	for key, flow := range sc.flows {
		flow.mu.Lock()
		if now.Sub(flow.lastSeen) > sc.config.WindowSize {
			expired = append(expired, key)
		}
		flow.mu.Unlock()
	}
	sc.flowMu.RUnlock()
	
	// Remove expired flows
	if len(expired) > 0 {
		sc.flowMu.Lock()
		for _, key := range expired {
			delete(sc.flows, key)
		}
		sc.flowMu.Unlock()
		
		sc.updateStats(func(stats *CorrelationStats) {
			stats.ActiveFlows -= int64(len(expired))
		})
	}
}

// hashFlowKey creates a hash of the flow key for worker assignment
func (sc *streamingCorrelatorImpl) hashFlowKey(key types.FlowKey) int {
	// Simple hash function
	hash := 0
	for _, b := range []byte(string(key)) {
		hash = hash*31 + int(b)
	}
	if hash < 0 {
		hash = -hash
	}
	return hash
}

// updateStats safely updates correlation statistics
func (sc *streamingCorrelatorImpl) updateStats(update func(*CorrelationStats)) {
	sc.statsMu.Lock()
	defer sc.statsMu.Unlock()
	update(&sc.stats)
}

// Correlations returns the correlation results channel
func (sc *streamingCorrelatorImpl) Correlations() <-chan LiveCorrelation {
	return sc.correlations
}

// GetStats returns current correlation statistics
func (sc *streamingCorrelatorImpl) GetStats() CorrelationStats {
	sc.statsMu.Lock()
	defer sc.statsMu.Unlock()
	
	// Calculate window utilization
	sc.flowMu.RLock()
	currentFlows := int64(len(sc.flows))
	sc.flowMu.RUnlock()
	
	stats := sc.stats
	stats.ActiveFlows = currentFlows
	stats.WindowUtilization = float64(currentFlows) / float64(sc.config.MaxFlows)
	
	return stats
}

// GetWindowSize returns the correlation window size
func (sc *streamingCorrelatorImpl) GetWindowSize() time.Duration {
	return sc.config.WindowSize
}

// GetMaxFlows returns the maximum number of flows
func (sc *streamingCorrelatorImpl) GetMaxFlows() int {
	return sc.config.MaxFlows
}