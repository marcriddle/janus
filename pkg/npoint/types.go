package npoint

import (
	"fmt"
	"sync"
	"time"

	"github.com/janus-project/janus/pkg/types"
)

// CapturePoint represents a single packet capture location
type CapturePoint struct {
	ID       string
	Name     string
	Location string // Physical or logical location
	Metadata map[string]string
}

// PacketObservation represents a packet seen at a specific capture point
type PacketObservation struct {
	PointID   string
	Timestamp time.Time
	Packet    types.PacketInfo
	FlowKey   types.FlowKey
}

// FlowPath represents the complete journey of a flow across multiple capture points
type FlowPath struct {
	FlowKey      types.FlowKey
	Observations []PacketObservation // Ordered by timestamp
	Points       []string            // Unique capture points in order
	FirstSeen    time.Time
	LastSeen     time.Time
	PacketCount  int
	mu           sync.RWMutex
}

// AddObservation adds a new packet observation to the flow path
func (fp *FlowPath) AddObservation(obs PacketObservation) {
	fp.mu.Lock()
	defer fp.mu.Unlock()

	fp.Observations = append(fp.Observations, obs)
	fp.PacketCount++

	if fp.FirstSeen.IsZero() || obs.Timestamp.Before(fp.FirstSeen) {
		fp.FirstSeen = obs.Timestamp
	}
	if obs.Timestamp.After(fp.LastSeen) {
		fp.LastSeen = obs.Timestamp
	}

	// Update unique points
	found := false
	for _, p := range fp.Points {
		if p == obs.PointID {
			found = true
			break
		}
	}
	if !found {
		fp.Points = append(fp.Points, obs.PointID)
	}
}

// GetObservations returns a copy of all observations
func (fp *FlowPath) GetObservations() []PacketObservation {
	fp.mu.RLock()
	defer fp.mu.RUnlock()
	
	result := make([]PacketObservation, len(fp.Observations))
	copy(result, fp.Observations)
	return result
}

// GetLatency calculates the latency between first and last observation
func (fp *FlowPath) GetLatency() time.Duration {
	fp.mu.RLock()
	defer fp.mu.RUnlock()
	
	if len(fp.Observations) < 2 {
		return 0
	}
	return fp.LastSeen.Sub(fp.FirstSeen)
}

// GetHopCount returns the number of unique capture points
func (fp *FlowPath) GetHopCount() int {
	fp.mu.RLock()
	defer fp.mu.RUnlock()
	
	return len(fp.Points)
}

// CorrelationMatch represents a match between packets at different points
type CorrelationMatch struct {
	FlowKey     types.FlowKey
	Points      []string // Capture points involved
	MatchType   string   // "ipid", "payload", "tcp_seq", "flow", "timing"
	Confidence  float64
	Latency     time.Duration
	PacketCount int
}

// NPointCorrelationResult represents the result of N-point correlation analysis
type NPointCorrelationResult struct {
	TotalFlows      int
	CorrelatedFlows int
	FlowPaths       map[types.FlowKey]*FlowPath
	Matches         []CorrelationMatch
	
	// Performance metrics
	ProcessingTime  time.Duration
	PacketsAnalyzed int64
	MemoryUsed      int64
	
	// Analysis metadata
	CapturePoints   []CapturePoint
	TimeRange       TimeRange
	AnalysisMethod  string
}

// TimeRange represents a time window
type TimeRange struct {
	Start time.Time
	End   time.Time
}

// Duration returns the duration of the time range
func (tr TimeRange) Duration() time.Duration {
	return tr.End.Sub(tr.Start)
}

// Contains checks if a timestamp falls within the range
func (tr TimeRange) Contains(t time.Time) bool {
	return !t.Before(tr.Start) && !t.After(tr.End)
}

// FlowGraph represents flows as a directed graph between capture points
type FlowGraph struct {
	Nodes map[string]*GraphNode // Key is capture point ID
	Edges []*GraphEdge
	mu    sync.RWMutex
}

// GraphNode represents a capture point in the flow graph
type GraphNode struct {
	PointID      string
	Point        CapturePoint
	IncomingFlows  int
	OutgoingFlows  int
	TotalPackets   int64
}

// GraphEdge represents flows between two capture points
type GraphEdge struct {
	Source      string
	Destination string
	FlowCount   int
	PacketCount int64
	AvgLatency  time.Duration
	Flows       []types.FlowKey
}

// AddFlow adds a flow to the graph
func (fg *FlowGraph) AddFlow(path *FlowPath) {
	fg.mu.Lock()
	defer fg.mu.Unlock()
	
	if len(path.Points) < 2 {
		return
	}
	
	// Update nodes
	for _, pointID := range path.Points {
		if node, exists := fg.Nodes[pointID]; exists {
			node.TotalPackets += int64(path.PacketCount)
		}
	}
	
	// Update edges
	for i := 0; i < len(path.Points)-1; i++ {
		src := path.Points[i]
		dst := path.Points[i+1]
		
		// Find or create edge
		var edge *GraphEdge
		for _, e := range fg.Edges {
			if e.Source == src && e.Destination == dst {
				edge = e
				break
			}
		}
		
		if edge == nil {
			edge = &GraphEdge{
				Source:      src,
				Destination: dst,
				Flows:       []types.FlowKey{},
			}
			fg.Edges = append(fg.Edges, edge)
		}
		
		edge.FlowCount++
		edge.PacketCount += int64(path.PacketCount)
		edge.Flows = append(edge.Flows, path.FlowKey)
		
		// Update node flow counts
		if srcNode, exists := fg.Nodes[src]; exists {
			srcNode.OutgoingFlows++
		}
		if dstNode, exists := fg.Nodes[dst]; exists {
			dstNode.IncomingFlows++
		}
	}
}

// GetTopPaths returns the most common flow paths
func (fg *FlowGraph) GetTopPaths(limit int) [][]string {
	fg.mu.RLock()
	defer fg.mu.RUnlock()
	
	// Group paths by sequence
	pathCounts := make(map[string]int)
	pathSequences := make(map[string][]string)
	
	for _, edge := range fg.Edges {
		pathKey := fmt.Sprintf("%s->%s", edge.Source, edge.Destination)
		pathCounts[pathKey] = edge.FlowCount
		pathSequences[pathKey] = []string{edge.Source, edge.Destination}
	}
	
	// Sort by count and return top paths
	// (Simplified for now, can be enhanced with proper sorting)
	var result [][]string
	for _, seq := range pathSequences {
		result = append(result, seq)
		if len(result) >= limit {
			break
		}
	}
	
	return result
}

// CorrelationStrategy represents different correlation algorithms
type CorrelationStrategy interface {
	Name() string
	Correlate(observations []PacketObservation) []CorrelationMatch
}

// NPointConfig holds configuration for N-point correlation
type NPointConfig struct {
	// Correlation parameters
	MaxTimeDelta      time.Duration
	MinConfidence     float64
	EnablePayloadHash bool
	EnableTCPSeq      bool
	EnableIPID        bool
	EnableTiming      bool
	
	// Performance tuning
	WorkerCount       int
	BatchSize         int
	MaxMemoryMB       int
	
	// Analysis options
	TrackBidirectional bool
	IncludePartialPaths bool
}

// DefaultNPointConfig returns a default configuration
func DefaultNPointConfig() *NPointConfig {
	return &NPointConfig{
		MaxTimeDelta:      5 * time.Second,
		MinConfidence:     0.7,
		EnablePayloadHash: true,
		EnableTCPSeq:      true,
		EnableIPID:        true,
		EnableTiming:      true,
		WorkerCount:       4,
		BatchSize:         1000,
		MaxMemoryMB:       1024,
		TrackBidirectional: true,
		IncludePartialPaths: false,
	}
}