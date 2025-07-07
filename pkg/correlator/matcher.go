package correlator

import (
	"fmt"

	"github.com/janus-project/janus/pkg/types"
)

// MatchStrategy represents different packet matching strategies
type MatchStrategy int

const (
	// MatchIPID uses IP Identification field matching
	MatchIPID MatchStrategy = iota
	// MatchTCPSeq uses TCP sequence numbers
	MatchTCPSeq
	// MatchPayloadHash uses payload content hash
	MatchPayloadHash
	// MatchTTLPattern uses TTL decrement patterns
	MatchTTLPattern
)

// MatchResult represents the result of a packet matching attempt
type MatchResult struct {
	Matched      bool
	Strategy     MatchStrategy
	Confidence   float64 // 0.0 to 1.0
	Description  string
}

// PacketMatcher implements multiple strategies for packet correlation
type PacketMatcher struct {
	strategies []MatchStrategy
}

// NewPacketMatcher creates a new packet matcher with default strategies
func NewPacketMatcher() *PacketMatcher {
	return &PacketMatcher{
		strategies: []MatchStrategy{
			MatchPayloadHash, // Highest confidence
			MatchTCPSeq,      // High confidence for TCP
			MatchIPID,        // Medium confidence
			MatchTTLPattern,  // Low confidence, corroborative
		},
	}
}

// Match attempts to match two packet observations using multiple strategies
func (pm *PacketMatcher) Match(p1, p2 *types.CapturePointInfo, streamData map[types.FlowKey]string) MatchResult {
	// Try each strategy in order of confidence
	for _, strategy := range pm.strategies {
		result := pm.tryStrategy(strategy, p1, p2, streamData)
		if result.Matched {
			return result
		}
	}
	
	return MatchResult{
		Matched:     false,
		Confidence:  0.0,
		Description: "No matching strategy succeeded",
	}
}

func (pm *PacketMatcher) tryStrategy(strategy MatchStrategy, p1, p2 *types.CapturePointInfo, streamData map[types.FlowKey]string) MatchResult {
	switch strategy {
	case MatchPayloadHash:
		return pm.matchByPayloadHash(p1, p2, streamData)
	case MatchTCPSeq:
		return pm.matchByTCPSeq(p1, p2)
	case MatchIPID:
		return pm.matchByIPID(p1, p2)
	case MatchTTLPattern:
		return pm.matchByTTLPattern(p1, p2)
	default:
		return MatchResult{Matched: false}
	}
}

// matchByPayloadHash matches packets based on reassembled stream payload hash
func (pm *PacketMatcher) matchByPayloadHash(p1, p2 *types.CapturePointInfo, streamData map[types.FlowKey]string) MatchResult {
	// Check if we have stream data for both flows
	flow1 := types.NewFlowKey(p1.Packet.Protocol, p1.Packet.SrcIP, p1.Packet.SrcPort, p1.Packet.DstIP, p1.Packet.DstPort)
	flow2 := types.NewFlowKey(p2.Packet.Protocol, p2.Packet.SrcIP, p2.Packet.SrcPort, p2.Packet.DstIP, p2.Packet.DstPort)
	
	hash1, has1 := streamData[flow1]
	hash2, has2 := streamData[flow2]
	
	if has1 && has2 && hash1 != "" && hash2 != "" && hash1 == hash2 {
		return MatchResult{
			Matched:     true,
			Strategy:    MatchPayloadHash,
			Confidence:  0.99, // Very high confidence
			Description: fmt.Sprintf("Payload hash match: %s", hash1[:16]+"..."),
		}
	}
	
	return MatchResult{Matched: false}
}

// matchByTCPSeq matches TCP packets by sequence numbers
func (pm *PacketMatcher) matchByTCPSeq(p1, p2 *types.CapturePointInfo) MatchResult {
	// Only applicable to TCP
	if p1.Packet.Protocol != "tcp" || p2.Packet.Protocol != "tcp" {
		return MatchResult{Matched: false}
	}
	
	// Both must have sequence numbers
	if p1.Packet.TCPSeq == 0 || p2.Packet.TCPSeq == 0 {
		return MatchResult{Matched: false}
	}
	
	// Check for exact match or expected progression
	if p1.Packet.TCPSeq == p2.Packet.TCPSeq {
		return MatchResult{
			Matched:     true,
			Strategy:    MatchTCPSeq,
			Confidence:  0.85,
			Description: fmt.Sprintf("TCP sequence match: %d", p1.Packet.TCPSeq),
		}
	}
	
	return MatchResult{Matched: false}
}

// matchByIPID matches packets by IP Identification field
func (pm *PacketMatcher) matchByIPID(p1, p2 *types.CapturePointInfo) MatchResult {
	// Must have same source IP and non-zero IP ID
	if !p1.Packet.SrcIP.Equal(p2.Packet.SrcIP) || p1.Packet.IPID == 0 {
		return MatchResult{Matched: false}
	}
	
	if p1.Packet.IPID == p2.Packet.IPID {
		return MatchResult{
			Matched:     true,
			Strategy:    MatchIPID,
			Confidence:  0.7, // Medium confidence due to potential collisions
			Description: fmt.Sprintf("IP ID match: %d", p1.Packet.IPID),
		}
	}
	
	return MatchResult{Matched: false}
}

// matchByTTLPattern matches packets by expected TTL decrements
func (pm *PacketMatcher) matchByTTLPattern(p1, p2 *types.CapturePointInfo) MatchResult {
	// This is a corroborative check, not primary matching
	// Used in combination with other matches
	
	// Check if TTL decremented by expected amount (1-3 hops typical)
	ttlDiff := int(p1.Packet.TTL) - int(p2.Packet.TTL)
	if ttlDiff >= 1 && ttlDiff <= 3 {
		return MatchResult{
			Matched:     true,
			Strategy:    MatchTTLPattern,
			Confidence:  0.3, // Low confidence, corroborative only
			Description: fmt.Sprintf("TTL pattern match: %d -> %d (%d hops)", p1.Packet.TTL, p2.Packet.TTL, ttlDiff),
		}
	}
	
	return MatchResult{Matched: false}
}

// CombineMatches combines multiple match results for higher confidence
func CombineMatches(primary MatchResult, secondary ...MatchResult) MatchResult {
	if !primary.Matched {
		return primary
	}
	
	combined := primary
	confidence := primary.Confidence
	
	// Boost confidence with corroborative matches
	for _, match := range secondary {
		if match.Matched {
			// Add partial confidence boost
			confidence += match.Confidence * 0.1
			combined.Description += "; " + match.Description
		}
	}
	
	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}
	
	combined.Confidence = confidence
	return combined
}