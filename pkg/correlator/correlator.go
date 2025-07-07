package correlator

import (
	"fmt"
	"sync"
	"time"

	"github.com/janus-project/janus/pkg/types"
)

// Correlator manages the correlation of packets across multiple capture points
type Correlator struct {
	// Map of flow key to flow trace
	flows map[types.FlowKey]*types.FlowTrace
	
	// Map for IP ID based correlation
	// Key is "srcIP:IPID", value is list of observations
	ipidMap map[string][]*types.CapturePointInfo
	
	mu sync.RWMutex
}

// New creates a new correlator instance
func New() *Correlator {
	return &Correlator{
		flows:   make(map[types.FlowKey]*types.FlowTrace),
		ipidMap: make(map[string][]*types.CapturePointInfo),
	}
}

// ProcessPacket processes a packet observation from a capture point
func (c *Correlator) ProcessPacket(capture *types.CapturePointInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Create flow key
	flowKey := types.NewFlowKey(
		capture.Packet.Protocol,
		capture.Packet.SrcIP,
		capture.Packet.SrcPort,
		capture.Packet.DstIP,
		capture.Packet.DstPort,
	)

	// Get or create flow trace
	flow, exists := c.flows[flowKey]
	if !exists {
		flow = &types.FlowTrace{}
		c.flows[flowKey] = flow
	}

	// Add observation to flow
	flow.AddObservation(*capture)

	// For Phase 1: Store in IP ID map for correlation
	if capture.Packet.IPID != 0 {
		ipidKey := fmt.Sprintf("%s:%d", capture.Packet.SrcIP, capture.Packet.IPID)
		c.ipidMap[ipidKey] = append(c.ipidMap[ipidKey], capture)
	}
}

// CorrelationResult represents the result of correlating packets between two points
type CorrelationResult struct {
	Flow            types.FlowKey
	Point1          types.CapturePointInfo
	Point2          types.CapturePointInfo
	Latency         time.Duration
	PacketModified  bool
	Modifications   []string
}

// CorrelatePackets performs IP ID-based correlation between two capture points
func (c *Correlator) CorrelatePackets(point1ID, point2ID string) []CorrelationResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var results []CorrelationResult

	// For each IP ID group, look for packets from both capture points
	for _, observations := range c.ipidMap {
		var point1Packets []*types.CapturePointInfo
		var point2Packets []*types.CapturePointInfo

		// Separate observations by capture point
		for _, obs := range observations {
			if obs.PointID == point1ID {
				point1Packets = append(point1Packets, obs)
			} else if obs.PointID == point2ID {
				point2Packets = append(point2Packets, obs)
			}
		}

		// If we have packets from both points, correlate them
		if len(point1Packets) > 0 && len(point2Packets) > 0 {
			// For Phase 1, use simple correlation: match packets with same IP ID
			// In real scenarios, we'd need more sophisticated matching
			for _, p1 := range point1Packets {
				for _, p2 := range point2Packets {
					if c.packetsMatch(p1, p2) {
						result := c.analyzeCorrelation(p1, p2)
						results = append(results, result)
					}
				}
			}
		}
	}

	return results
}

// packetsMatch determines if two packet observations represent the same packet
func (c *Correlator) packetsMatch(p1, p2 *types.CapturePointInfo) bool {
	// Phase 1: Simple IP ID matching with same flow
	if p1.Packet.IPID != p2.Packet.IPID {
		return false
	}

	// Must be from same source IP
	if !p1.Packet.SrcIP.Equal(p2.Packet.SrcIP) {
		return false
	}

	// For TCP, check sequence numbers if available
	if p1.Packet.Protocol == "tcp" && p2.Packet.Protocol == "tcp" {
		if p1.Packet.TCPSeq != 0 && p2.Packet.TCPSeq != 0 {
			return p1.Packet.TCPSeq == p2.Packet.TCPSeq
		}
	}

	return true
}

// analyzeCorrelation analyzes the correlation between two packet observations
func (c *Correlator) analyzeCorrelation(p1, p2 *types.CapturePointInfo) CorrelationResult {
	result := CorrelationResult{
		Flow:   types.NewFlowKey(p1.Packet.Protocol, p1.Packet.SrcIP, p1.Packet.SrcPort, p1.Packet.DstIP, p1.Packet.DstPort),
		Point1: *p1,
		Point2: *p2,
	}

	// Calculate latency
	if p2.Packet.Timestamp.After(p1.Packet.Timestamp) {
		result.Latency = p2.Packet.Timestamp.Sub(p1.Packet.Timestamp)
	} else {
		result.Latency = p1.Packet.Timestamp.Sub(p2.Packet.Timestamp)
	}

	// Check for modifications
	result.Modifications = c.detectModifications(p1, p2)
	result.PacketModified = len(result.Modifications) > 0

	return result
}

// detectModifications detects changes between two packet observations
func (c *Correlator) detectModifications(p1, p2 *types.CapturePointInfo) []string {
	var mods []string

	// Check TTL decrement
	if p1.Packet.TTL != p2.Packet.TTL {
		expectedTTL := p1.Packet.TTL - 1
		if p2.Packet.TTL == expectedTTL {
			mods = append(mods, fmt.Sprintf("TTL decremented: %d -> %d (1 hop)", p1.Packet.TTL, p2.Packet.TTL))
		} else {
			mods = append(mods, fmt.Sprintf("TTL changed: %d -> %d", p1.Packet.TTL, p2.Packet.TTL))
		}
	}

	// Check for NAT (Phase 3 feature, but basic detection here)
	if !p1.Packet.SrcIP.Equal(p2.Packet.SrcIP) || p1.Packet.SrcPort != p2.Packet.SrcPort {
		mods = append(mods, fmt.Sprintf("Source NAT detected: %s:%d -> %s:%d", 
			p1.Packet.SrcIP, p1.Packet.SrcPort, p2.Packet.SrcIP, p2.Packet.SrcPort))
	}

	if !p1.Packet.DstIP.Equal(p2.Packet.DstIP) || p1.Packet.DstPort != p2.Packet.DstPort {
		mods = append(mods, fmt.Sprintf("Destination NAT detected: %s:%d -> %s:%d", 
			p1.Packet.DstIP, p1.Packet.DstPort, p2.Packet.DstIP, p2.Packet.DstPort))
	}

	return mods
}

// GetFlowSummary returns a summary of all tracked flows
func (c *Correlator) GetFlowSummary() map[types.FlowKey][]types.CapturePointInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	summary := make(map[types.FlowKey][]types.CapturePointInfo)
	for flowKey, flowTrace := range c.flows {
		summary[flowKey] = flowTrace.GetPath()
	}
	return summary
}