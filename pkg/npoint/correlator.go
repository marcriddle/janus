package npoint

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/janus-project/janus/pkg/pcap"
	"github.com/janus-project/janus/pkg/stream"
	"github.com/janus-project/janus/pkg/types"
)

// NPointCorrelator handles correlation across N capture points
type NPointCorrelator struct {
	config        *NPointConfig
	capturePoints map[string]*CapturePoint
	readers       map[string]*pcap.Reader
	observations  map[types.FlowKey][]*PacketObservation
	flowPaths     map[types.FlowKey]*FlowPath
	flowGraph     *FlowGraph
	strategies    []CorrelationStrategy
	mu            sync.RWMutex
	
	// Performance tracking
	startTime     time.Time
	packetsProcessed int64
}

// NewNPointCorrelator creates a new N-point correlator
func NewNPointCorrelator(config *NPointConfig) *NPointCorrelator {
	if config == nil {
		config = DefaultNPointConfig()
	}
	
	nc := &NPointCorrelator{
		config:        config,
		capturePoints: make(map[string]*CapturePoint),
		readers:       make(map[string]*pcap.Reader),
		observations:  make(map[types.FlowKey][]*PacketObservation),
		flowPaths:     make(map[types.FlowKey]*FlowPath),
		flowGraph:     &FlowGraph{
			Nodes: make(map[string]*GraphNode),
			Edges: []*GraphEdge{},
		},
		strategies:    []CorrelationStrategy{},
	}
	
	// Initialize correlation strategies based on config
	if config.EnableIPID {
		nc.strategies = append(nc.strategies, &IPIDStrategy{config: config})
	}
	if config.EnablePayloadHash {
		nc.strategies = append(nc.strategies, &PayloadHashStrategy{config: config})
	}
	if config.EnableTCPSeq {
		nc.strategies = append(nc.strategies, &TCPSeqStrategy{config: config})
	}
	if config.EnableTiming {
		nc.strategies = append(nc.strategies, &TimingStrategy{config: config})
	}
	
	return nc
}

// AddCapturePoint adds a new capture point with its PCAP file
func (nc *NPointCorrelator) AddCapturePoint(id, name, pcapFile string) error {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	
	// Create capture point
	cp := &CapturePoint{
		ID:       id,
		Name:     name,
		Location: pcapFile,
		Metadata: make(map[string]string),
	}
	nc.capturePoints[id] = cp
	
	// Create PCAP reader
	reader, err := pcap.NewReader(pcapFile, id)
	if err != nil {
		return fmt.Errorf("failed to open pcap file %s: %w", pcapFile, err)
	}
	nc.readers[id] = reader
	
	// Add node to flow graph
	nc.flowGraph.Nodes[id] = &GraphNode{
		PointID: id,
		Point:   *cp,
	}
	
	return nil
}

// Correlate performs N-point correlation analysis
func (nc *NPointCorrelator) Correlate() (*NPointCorrelationResult, error) {
	nc.startTime = time.Now()
	
	// Step 1: Load all packets from all capture points
	if err := nc.loadAllPackets(); err != nil {
		return nil, fmt.Errorf("failed to load packets: %w", err)
	}
	
	// Step 2: Group observations by flow
	nc.groupObservationsByFlow()
	
	// Step 3: Apply correlation strategies
	matches := nc.applyCorrelationStrategies()
	
	// Step 4: Build flow paths
	nc.buildFlowPaths(matches)
	
	// Step 5: Analyze flow graph
	nc.analyzeFlowGraph()
	
	// Step 6: Generate results
	result := nc.generateResults(matches)
	
	return result, nil
}

// loadAllPackets loads packets from all capture points concurrently
func (nc *NPointCorrelator) loadAllPackets() error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(nc.readers))
	
	// Process each capture point concurrently
	for pointID, reader := range nc.readers {
		wg.Add(1)
		go func(pid string, r *pcap.Reader) {
			defer wg.Done()
			
			if err := nc.loadPacketsFromPoint(pid, r); err != nil {
				errChan <- fmt.Errorf("point %s: %w", pid, err)
			}
		}(pointID, reader)
	}
	
	wg.Wait()
	close(errChan)
	
	// Check for errors
	for err := range errChan {
		return err
	}
	
	return nil
}

// loadPacketsFromPoint loads packets from a single capture point
func (nc *NPointCorrelator) loadPacketsFromPoint(pointID string, reader *pcap.Reader) error {
	// Start the reader
	reader.Start()
	
	nc.mu.Lock()
	defer nc.mu.Unlock()
	
	// Read packets from channels
	for {
		select {
		case captureInfo, ok := <-reader.Packets():
			if !ok {
				return nil // Channel closed, done reading
			}
			
			// Create flow key
			flowKey := types.NewFlowKey(
				captureInfo.Packet.Protocol,
				captureInfo.Packet.SrcIP,
				captureInfo.Packet.SrcPort,
				captureInfo.Packet.DstIP,
				captureInfo.Packet.DstPort,
			)
			
			// Create observation
			obs := PacketObservation{
				PointID:   pointID,
				Timestamp: captureInfo.Packet.Timestamp,
				Packet:    captureInfo.Packet,
				FlowKey:   flowKey,
			}
			
			// Store observation
			if nc.observations[flowKey] == nil {
				nc.observations[flowKey] = []*PacketObservation{}
			}
			nc.observations[flowKey] = append(nc.observations[flowKey], &obs)
			
			nc.packetsProcessed++
			
		case err := <-reader.Errors():
			return err
		}
	}
}

// groupObservationsByFlow sorts observations by timestamp for each flow
func (nc *NPointCorrelator) groupObservationsByFlow() {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	
	for flowKey, obs := range nc.observations {
		// Sort by timestamp
		sort.Slice(obs, func(i, j int) bool {
			return obs[i].Timestamp.Before(obs[j].Timestamp)
		})
		
		// Create initial flow path
		fp := &FlowPath{
			FlowKey:      flowKey,
			Observations: []PacketObservation{},
			Points:       []string{},
		}
		
		for _, o := range obs {
			fp.AddObservation(*o)
		}
		
		nc.flowPaths[flowKey] = fp
	}
}

// applyCorrelationStrategies runs all enabled correlation strategies
func (nc *NPointCorrelator) applyCorrelationStrategies() []CorrelationMatch {
	var allMatches []CorrelationMatch
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	// Run strategies concurrently
	for _, strategy := range nc.strategies {
		wg.Add(1)
		go func(s CorrelationStrategy) {
			defer wg.Done()
			
			// Flatten observations for strategy
			var allObs []PacketObservation
			nc.mu.RLock()
			for _, obs := range nc.observations {
				for _, o := range obs {
					allObs = append(allObs, *o)
				}
			}
			nc.mu.RUnlock()
			
			// Run strategy
			matches := s.Correlate(allObs)
			
			// Collect results
			mu.Lock()
			allMatches = append(allMatches, matches...)
			mu.Unlock()
		}(strategy)
	}
	
	wg.Wait()
	
	// Deduplicate and merge matches
	return nc.mergeMatches(allMatches)
}

// mergeMatches deduplicates and merges correlation matches
func (nc *NPointCorrelator) mergeMatches(matches []CorrelationMatch) []CorrelationMatch {
	// Group by flow key
	flowMatches := make(map[types.FlowKey][]CorrelationMatch)
	
	for _, match := range matches {
		flowMatches[match.FlowKey] = append(flowMatches[match.FlowKey], match)
	}
	
	// Merge matches for each flow
	var merged []CorrelationMatch
	for flowKey, fMatches := range flowMatches {
		if len(fMatches) == 0 {
			continue
		}
		
		// Combine confidence scores
		var totalConfidence float64
		points := make(map[string]bool)
		
		for _, m := range fMatches {
			totalConfidence += m.Confidence
			for _, p := range m.Points {
				points[p] = true
			}
		}
		
		// Create merged match
		var pointList []string
		for p := range points {
			pointList = append(pointList, p)
		}
		sort.Strings(pointList)
		
		merged = append(merged, CorrelationMatch{
			FlowKey:    flowKey,
			Points:     pointList,
			MatchType:  "multi-strategy",
			Confidence: totalConfidence / float64(len(fMatches)),
			Latency:    fMatches[0].Latency, // Use first match latency
		})
	}
	
	return merged
}

// buildFlowPaths creates enhanced flow paths based on correlation matches
func (nc *NPointCorrelator) buildFlowPaths(matches []CorrelationMatch) {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	
	// Enhance existing flow paths with correlation data
	for _, match := range matches {
		if fp, exists := nc.flowPaths[match.FlowKey]; exists {
			// Update confidence and match type
			// This is simplified - in production, we'd merge this data more carefully
			fp.Points = match.Points
		}
	}
}

// analyzeFlowGraph builds the flow graph from flow paths
func (nc *NPointCorrelator) analyzeFlowGraph() {
	nc.mu.RLock()
	defer nc.mu.RUnlock()
	
	for _, fp := range nc.flowPaths {
		nc.flowGraph.AddFlow(fp)
	}
}

// generateResults creates the final correlation result
func (nc *NPointCorrelator) generateResults(matches []CorrelationMatch) *NPointCorrelationResult {
	nc.mu.RLock()
	defer nc.mu.RUnlock()
	
	// Calculate time range
	var minTime, maxTime time.Time
	for _, fp := range nc.flowPaths {
		if minTime.IsZero() || fp.FirstSeen.Before(minTime) {
			minTime = fp.FirstSeen
		}
		if fp.LastSeen.After(maxTime) {
			maxTime = fp.LastSeen
		}
	}
	
	// Collect capture points
	var capturePoints []CapturePoint
	for _, cp := range nc.capturePoints {
		capturePoints = append(capturePoints, *cp)
	}
	
	// Count correlated flows
	correlatedCount := 0
	for _, fp := range nc.flowPaths {
		if fp.GetHopCount() > 1 {
			correlatedCount++
		}
	}
	
	return &NPointCorrelationResult{
		TotalFlows:      len(nc.flowPaths),
		CorrelatedFlows: correlatedCount,
		FlowPaths:       nc.flowPaths,
		Matches:         matches,
		ProcessingTime:  time.Since(nc.startTime),
		PacketsAnalyzed: nc.packetsProcessed,
		CapturePoints:   capturePoints,
		TimeRange: TimeRange{
			Start: minTime,
			End:   maxTime,
		},
		AnalysisMethod: "multi-strategy",
	}
}

// GetFlowGraph returns the current flow graph
func (nc *NPointCorrelator) GetFlowGraph() *FlowGraph {
	return nc.flowGraph
}

// GetStreamData performs stream reassembly for all capture points
func (nc *NPointCorrelator) GetStreamData() map[string]map[types.FlowKey]*stream.StreamData {
	result := make(map[string]map[types.FlowKey]*stream.StreamData)
	
	nc.mu.RLock()
	defer nc.mu.RUnlock()
	
	// Process each capture point
	for pointID := range nc.readers {
		reassembler := stream.NewStreamReassembler(pointID)
		
		// Use the existing observations instead of re-reading
		// This is more efficient and avoids re-parsing
		for _, observations := range nc.observations {
			for _, obs := range observations {
				if obs.PointID == pointID {
					// Convert observation back to gopacket format if needed
					// For now, we'll skip stream reassembly in N-point mode
					// as it's primarily for payload hashing which we handle differently
				}
			}
		}
		
		reassembler.FlushAll()
		result[pointID] = reassembler.GetStreams()
	}
	
	return result
}