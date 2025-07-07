package correlator

import (
	"fmt"
	"sync"
	"time"

	"github.com/janus-project/janus/pkg/stream"
	"github.com/janus-project/janus/pkg/types"
)

// Phase 2 additions to the Correlator

// Enhanced Correlator fields for Phase 2
type CorrelatorPhase2 struct {
	*Correlator
	
	// Stream data from reassembly
	streamData map[string]map[types.FlowKey]*stream.StreamData
	
	// Packet matcher for multi-strategy correlation
	matcher *PacketMatcher
	
	// Configuration options
	skipTTLOnly bool
}

// NewPhase2 creates a new correlator with Phase 2 features
func NewPhase2() *CorrelatorPhase2 {
	return &CorrelatorPhase2{
		Correlator:  New(),
		streamData:  make(map[string]map[types.FlowKey]*stream.StreamData),
		matcher:     NewPacketMatcher(),
		skipTTLOnly: false,
	}
}

// SetStreamData sets the reassembled stream data for a capture point
func (c *CorrelatorPhase2) SetStreamData(pointID string, streams map[types.FlowKey]*stream.StreamData) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.streamData[pointID] = streams
}

// SetSkipTTLOnly sets whether to skip packets that differ only by TTL (by 1 hop)
func (c *CorrelatorPhase2) SetSkipTTLOnly(skip bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.skipTTLOnly = skip
}

// Enhanced CorrelationResult for Phase 2
type CorrelationResultPhase2 struct {
	CorrelationResult
	MatchStrategy   string
	MatchConfidence float64
}

// CorrelatePacketsPhase2 performs enhanced correlation using multiple strategies
func (c *CorrelatorPhase2) CorrelatePacketsPhase2(point1ID, point2ID string) []CorrelationResultPhase2 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var results []CorrelationResultPhase2

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
			// Use multi-strategy matching
			for _, p1 := range point1Packets {
				for _, p2 := range point2Packets {
					matched, matchResult := c.packetsMatchPhase2(p1, p2)
					if matched {
						// Skip if configured to skip TTL-only differences
						if c.skipTTLOnly && c.isTTLOnlyDifference(p1, p2) {
							continue
						}
						
						result := c.analyzeCorrelationPhase2(p1, p2, matchResult)
						results = append(results, result)
					}
				}
			}
		}
	}

	return results
}

// packetsMatchPhase2 uses multiple strategies to match packets
func (c *CorrelatorPhase2) packetsMatchPhase2(p1, p2 *types.CapturePointInfo) (bool, MatchResult) {
	// Build stream hash map for payload matching
	streamHashes := make(map[types.FlowKey]string)
	
	// Get stream data for both points if available
	if streams1, ok := c.streamData[p1.PointID]; ok {
		for flow, data := range streams1 {
			if data.PayloadHash != "" {
				streamHashes[flow] = data.PayloadHash
			}
		}
	}
	if streams2, ok := c.streamData[p2.PointID]; ok {
		for flow, data := range streams2 {
			if data.PayloadHash != "" {
				streamHashes[flow] = data.PayloadHash
			}
		}
	}
	
	// Use the matcher to try multiple strategies
	result := c.matcher.Match(p1, p2, streamHashes)
	
	// Also try TTL pattern as corroborative evidence
	if result.Matched {
		ttlResult := c.matcher.tryStrategy(MatchTTLPattern, p1, p2, nil)
		if ttlResult.Matched {
			result = CombineMatches(result, ttlResult)
		}
	}
	
	return result.Matched, result
}

// analyzeCorrelationPhase2 creates an enhanced correlation result
func (c *CorrelatorPhase2) analyzeCorrelationPhase2(p1, p2 *types.CapturePointInfo, matchResult MatchResult) CorrelationResultPhase2 {
	// Use the base correlation analysis
	baseResult := c.analyzeCorrelation(p1, p2)
	
	return CorrelationResultPhase2{
		CorrelationResult: baseResult,
		MatchStrategy:     matchResult.Description,
		MatchConfidence:   matchResult.Confidence,
	}
}

// isTTLOnlyDifference checks if two packets differ only by TTL (by exactly 1 hop)
func (c *CorrelatorPhase2) isTTLOnlyDifference(p1, p2 *types.CapturePointInfo) bool {
	// Check if TTL differs by exactly 1
	ttlDiff := false
	if p1.Packet.TTL > p2.Packet.TTL && p1.Packet.TTL-p2.Packet.TTL == 1 {
		ttlDiff = true
	} else if p2.Packet.TTL > p1.Packet.TTL && p2.Packet.TTL-p1.Packet.TTL == 1 {
		ttlDiff = true
	}
	
	if !ttlDiff {
		return false
	}
	
	// Check that everything else is the same
	if !p1.Packet.SrcIP.Equal(p2.Packet.SrcIP) || p1.Packet.SrcPort != p2.Packet.SrcPort {
		return false
	}
	
	if !p1.Packet.DstIP.Equal(p2.Packet.DstIP) || p1.Packet.DstPort != p2.Packet.DstPort {
		return false
	}
	
	// All other fields are the same, only TTL differs by 1
	return true
}

// StreamCorrelationResult represents correlated TCP streams
type StreamCorrelationResult struct {
	Flow1          types.FlowKey
	Flow2          types.FlowKey
	Stream1        *stream.StreamData
	Stream2        *stream.StreamData
	PayloadHash    string
	Latency        time.Duration
	StreamModified bool
	Modifications  []string
}

// CorrelateStreams performs stream-based correlation between two capture points
func (c *CorrelatorPhase2) CorrelateStreams(point1ID, point2ID string) []StreamCorrelationResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var results []StreamCorrelationResult
	
	streams1, ok1 := c.streamData[point1ID]
	streams2, ok2 := c.streamData[point2ID]
	
	if !ok1 || !ok2 {
		return results
	}
	
	// Compare all streams by payload hash
	for flow1, data1 := range streams1 {
		if data1.PayloadHash == "" {
			continue
		}
		
		for flow2, data2 := range streams2 {
			if data2.PayloadHash == "" {
				continue
			}
			
			// Check if payload hashes match
			if data1.PayloadHash == data2.PayloadHash {
				result := StreamCorrelationResult{
					Flow1:       flow1,
					Flow2:       flow2,
					Stream1:     data1,
					Stream2:     data2,
					PayloadHash: data1.PayloadHash,
				}
				
				// Calculate latency based on first packet times
				if data2.FirstSeen.After(data1.FirstSeen) {
					result.Latency = data2.FirstSeen.Sub(data1.FirstSeen)
				} else {
					result.Latency = data1.FirstSeen.Sub(data2.FirstSeen)
				}
				
				// Detect modifications
				result.Modifications = c.detectStreamModifications(flow1, data1, flow2, data2)
				result.StreamModified = len(result.Modifications) > 0
				
				results = append(results, result)
			}
		}
	}
	
	return results
}

// detectStreamModifications detects changes between streams
func (c *CorrelatorPhase2) detectStreamModifications(flow1 types.FlowKey, stream1 *stream.StreamData, 
	flow2 types.FlowKey, stream2 *stream.StreamData) []string {
	
	var mods []string
	
	// Check for flow tuple changes (NAT)
	if string(flow1) != string(flow2) {
		mods = append(mods, fmt.Sprintf("Flow modified: %s -> %s (NAT detected)", flow1, flow2))
	}
	
	// Check payload size differences (possible middlebox modification)
	if stream1.PayloadSize != stream2.PayloadSize {
		mods = append(mods, fmt.Sprintf("Payload size changed: %d -> %d bytes", 
			stream1.PayloadSize, stream2.PayloadSize))
	}
	
	// Check packet count differences (possible fragmentation)
	if stream1.Packets != stream2.Packets {
		mods = append(mods, fmt.Sprintf("Packet count changed: %d -> %d (re-segmentation)", 
			stream1.Packets, stream2.Packets))
	}
	
	return mods
}