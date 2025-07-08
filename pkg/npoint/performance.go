package npoint

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/janus-project/janus/pkg/pcap"
	"github.com/janus-project/janus/pkg/types"
)

// PacketBatch represents a batch of packets for processing
type PacketBatch struct {
	Packets  []PacketObservation
	PointID  string
	BatchNum int
}

// WorkerPool manages concurrent packet processing
type WorkerPool struct {
	workerCount int
	batchSize   int
	inputChan   chan PacketBatch
	resultChan  chan []PacketObservation
	errorChan   chan error
	wg          sync.WaitGroup
	
	// Metrics
	packetsProcessed int64
	batchesProcessed int64
	startTime        time.Time
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(workerCount, batchSize int) *WorkerPool {
	if workerCount <= 0 {
		workerCount = runtime.NumCPU()
	}
	if batchSize <= 0 {
		batchSize = 1000
	}
	
	return &WorkerPool{
		workerCount: workerCount,
		batchSize:   batchSize,
		inputChan:   make(chan PacketBatch, workerCount*2),
		resultChan:  make(chan []PacketObservation, workerCount*2),
		errorChan:   make(chan error, workerCount),
		startTime:   time.Now(),
	}
}

// Start initializes the worker pool
func (wp *WorkerPool) Start() {
	for i := 0; i < wp.workerCount; i++ {
		wp.wg.Add(1)
		go wp.worker(i)
	}
}

// Stop gracefully shuts down the worker pool
func (wp *WorkerPool) Stop() {
	close(wp.inputChan)
	wp.wg.Wait()
	close(wp.resultChan)
	close(wp.errorChan)
}

// Submit adds a batch for processing
func (wp *WorkerPool) Submit(batch PacketBatch) {
	wp.inputChan <- batch
}

// Results returns the result channel
func (wp *WorkerPool) Results() <-chan []PacketObservation {
	return wp.resultChan
}

// Errors returns the error channel
func (wp *WorkerPool) Errors() <-chan error {
	return wp.errorChan
}

// GetMetrics returns processing metrics
func (wp *WorkerPool) GetMetrics() (packetsProcessed, batchesProcessed int64, duration time.Duration) {
	return atomic.LoadInt64(&wp.packetsProcessed),
		atomic.LoadInt64(&wp.batchesProcessed),
		time.Since(wp.startTime)
}

// worker processes batches
func (wp *WorkerPool) worker(id int) {
	defer wp.wg.Done()
	
	for batch := range wp.inputChan {
		processed := wp.processBatch(batch)
		
		atomic.AddInt64(&wp.packetsProcessed, int64(len(batch.Packets)))
		atomic.AddInt64(&wp.batchesProcessed, 1)
		
		wp.resultChan <- processed
	}
}

// processBatch processes a single batch of packets
func (wp *WorkerPool) processBatch(batch PacketBatch) []PacketObservation {
	// This is where packet-level optimizations would go
	// For now, just return the packets as-is
	return batch.Packets
}

// MemoryPool manages reusable memory buffers
type MemoryPool struct {
	obsPool    sync.Pool
	batchPool  sync.Pool
	bufferPool sync.Pool
}

// NewMemoryPool creates a new memory pool
func NewMemoryPool() *MemoryPool {
	return &MemoryPool{
		obsPool: sync.Pool{
			New: func() interface{} {
				return &PacketObservation{}
			},
		},
		batchPool: sync.Pool{
			New: func() interface{} {
				return &PacketBatch{
					Packets: make([]PacketObservation, 0, 1000),
				}
			},
		},
		bufferPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 65536) // 64KB buffer
			},
		},
	}
}

// GetObservation gets a packet observation from the pool
func (mp *MemoryPool) GetObservation() *PacketObservation {
	return mp.obsPool.Get().(*PacketObservation)
}

// PutObservation returns an observation to the pool
func (mp *MemoryPool) PutObservation(obs *PacketObservation) {
	// Reset the observation
	*obs = PacketObservation{}
	mp.obsPool.Put(obs)
}

// GetBatch gets a batch from the pool
func (mp *MemoryPool) GetBatch() *PacketBatch {
	return mp.batchPool.Get().(*PacketBatch)
}

// PutBatch returns a batch to the pool
func (mp *MemoryPool) PutBatch(batch *PacketBatch) {
	batch.Packets = batch.Packets[:0]
	batch.PointID = ""
	batch.BatchNum = 0
	mp.batchPool.Put(batch)
}

// GetBuffer gets a buffer from the pool
func (mp *MemoryPool) GetBuffer() []byte {
	return mp.bufferPool.Get().([]byte)
}

// PutBuffer returns a buffer to the pool
func (mp *MemoryPool) PutBuffer(buf []byte) {
	mp.bufferPool.Put(buf)
}

// FlowCache provides a fast lookup cache for flows
type FlowCache struct {
	cache map[types.FlowKey]*FlowPath
	mu    sync.RWMutex
	
	// LRU eviction
	maxSize int
	lru     *lruList
}

// lruList is a simple LRU list implementation
type lruList struct {
	head *lruNode
	tail *lruNode
	size int
}

type lruNode struct {
	key  types.FlowKey
	prev *lruNode
	next *lruNode
}

// NewFlowCache creates a new flow cache
func NewFlowCache(maxSize int) *FlowCache {
	return &FlowCache{
		cache:   make(map[types.FlowKey]*FlowPath),
		maxSize: maxSize,
		lru: &lruList{
			head: &lruNode{},
			tail: &lruNode{},
		},
	}
}

// Get retrieves a flow from the cache
func (fc *FlowCache) Get(key types.FlowKey) (*FlowPath, bool) {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	
	fp, exists := fc.cache[key]
	return fp, exists
}

// Put adds or updates a flow in the cache
func (fc *FlowCache) Put(key types.FlowKey, fp *FlowPath) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	
	// Check if we need to evict
	if len(fc.cache) >= fc.maxSize {
		if _, exists := fc.cache[key]; !exists {
			// Evict least recently used
			fc.evictLRU()
		}
	}
	
	fc.cache[key] = fp
}

// evictLRU removes the least recently used item
func (fc *FlowCache) evictLRU() {
	// Simple eviction - remove first item found
	// In production, this would be a proper LRU implementation
	for key := range fc.cache {
		delete(fc.cache, key)
		break
	}
}

// OptimizedCorrelator wraps the N-point correlator with performance optimizations
type OptimizedCorrelator struct {
	*NPointCorrelator
	workerPool *WorkerPool
	memPool    *MemoryPool
	flowCache  *FlowCache
}

// NewOptimizedCorrelator creates an optimized correlator
func NewOptimizedCorrelator(config *NPointConfig) *OptimizedCorrelator {
	if config == nil {
		config = DefaultNPointConfig()
	}
	
	return &OptimizedCorrelator{
		NPointCorrelator: NewNPointCorrelator(config),
		workerPool:       NewWorkerPool(config.WorkerCount, config.BatchSize),
		memPool:          NewMemoryPool(),
		flowCache:        NewFlowCache(10000), // Cache up to 10k flows
	}
}

// CorrelateOptimized performs optimized correlation
func (oc *OptimizedCorrelator) CorrelateOptimized() (*NPointCorrelationResult, error) {
	oc.startTime = time.Now()
	
	// Start worker pool
	oc.workerPool.Start()
	defer oc.workerPool.Stop()
	
	// Process packets in parallel batches
	var wg sync.WaitGroup
	
	// Launch reader goroutines
	for pointID, reader := range oc.readers {
		wg.Add(1)
		go func(pid string, r *pcap.Reader) {
			defer wg.Done()
			oc.processCapturePointOptimized(pid, r)
		}(pointID, reader)
	}
	
	// Collect results
	go func() {
		wg.Wait()
		// Signal completion
	}()
	
	// Process results as they come in
	for result := range oc.workerPool.Results() {
		oc.processResults(result)
	}
	
	// Apply correlation strategies
	matches := oc.applyCorrelationStrategies()
	
	// Build flow paths
	oc.buildFlowPaths(matches)
	
	// Analyze flow graph
	oc.analyzeFlowGraph()
	
	// Generate results
	result := oc.generateResults(matches)
	
	// Add performance metrics
	packets, _, duration := oc.workerPool.GetMetrics()
	result.ProcessingTime = duration
	result.PacketsAnalyzed = packets
	
	// Calculate throughput
	throughput := float64(packets) / duration.Seconds()
	result.AnalysisMethod = fmt.Sprintf("optimized (%d workers, %.0f pkt/s)", 
		oc.config.WorkerCount, throughput)
	
	return result, nil
}

// processCapturePointOptimized processes a capture point with optimization
func (oc *OptimizedCorrelator) processCapturePointOptimized(pointID string, reader *pcap.Reader) {
	batch := oc.memPool.GetBatch()
	batchNum := 0
	
	// Start the reader
	reader.Start()
	
	// Read packets from channels
	for {
		select {
		case captureInfo, ok := <-reader.Packets():
			if !ok {
				// Submit final batch if any packets remain
				if len(batch.Packets) > 0 {
					batch.PointID = pointID
					batch.BatchNum = batchNum
					oc.workerPool.Submit(*batch)
				}
				return
			}
			
			obs := PacketObservation{
				PointID:   pointID,
				Timestamp: captureInfo.Packet.Timestamp,
				Packet:    captureInfo.Packet,
				FlowKey: types.NewFlowKey(
					captureInfo.Packet.Protocol,
					captureInfo.Packet.SrcIP,
					captureInfo.Packet.SrcPort,
					captureInfo.Packet.DstIP,
					captureInfo.Packet.DstPort,
				),
			}
			
			batch.Packets = append(batch.Packets, obs)
			
			// Submit batch when full
			if len(batch.Packets) >= oc.config.BatchSize {
				batch.PointID = pointID
				batch.BatchNum = batchNum
				oc.workerPool.Submit(*batch)
				
				// Get new batch
				batch = oc.memPool.GetBatch()
				batchNum++
			}
			
		case err := <-reader.Errors():
			select {
			case oc.workerPool.errorChan <- err:
			default:
				// Error channel full, log and continue
			}
		}
	}
}

// processResults handles batch results
func (oc *OptimizedCorrelator) processResults(observations []PacketObservation) {
	oc.mu.Lock()
	defer oc.mu.Unlock()
	
	for _, obs := range observations {
		// Check cache first
		if fp, exists := oc.flowCache.Get(obs.FlowKey); exists {
			fp.AddObservation(obs)
		} else {
			// Add to observations
			if oc.observations[obs.FlowKey] == nil {
				oc.observations[obs.FlowKey] = []*PacketObservation{}
			}
			oc.observations[obs.FlowKey] = append(oc.observations[obs.FlowKey], &obs)
		}
		
		oc.packetsProcessed++
	}
}