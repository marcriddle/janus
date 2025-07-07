package npoint

import (
	"math"
	"sort"
	"time"

	"github.com/janus-project/janus/pkg/types"
)

// IPIDStrategy correlates packets based on IP ID field
type IPIDStrategy struct {
	config *NPointConfig
}

func (s *IPIDStrategy) Name() string {
	return "IP ID Correlation"
}

func (s *IPIDStrategy) Correlate(observations []PacketObservation) []CorrelationMatch {
	var matches []CorrelationMatch
	
	// Group by IP ID
	ipidGroups := make(map[uint16][]PacketObservation)
	for _, obs := range observations {
		if obs.Packet.IPID != 0 {
			ipidGroups[obs.Packet.IPID] = append(ipidGroups[obs.Packet.IPID], obs)
		}
	}
	
	// Find matches within time window
	for ipid, group := range ipidGroups {
		if len(group) < 2 {
			continue
		}
		
		// Sort by timestamp
		sort.Slice(group, func(i, j int) bool {
			return group[i].Timestamp.Before(group[j].Timestamp)
		})
		
		// Check time delta
		timeDelta := group[len(group)-1].Timestamp.Sub(group[0].Timestamp)
		if timeDelta > s.config.MaxTimeDelta {
			continue
		}
		
		// Collect unique points
		points := make(map[string]bool)
		for _, obs := range group {
			points[obs.PointID] = true
		}
		
		if len(points) < 2 {
			continue
		}
		
		// Create match
		var pointList []string
		for p := range points {
			pointList = append(pointList, p)
		}
		
		confidence := s.calculateConfidence(ipid, len(group), timeDelta)
		
		matches = append(matches, CorrelationMatch{
			FlowKey:     group[0].FlowKey,
			Points:      pointList,
			MatchType:   "ipid",
			Confidence:  confidence,
			Latency:     timeDelta,
			PacketCount: len(group),
		})
	}
	
	return matches
}

func (s *IPIDStrategy) calculateConfidence(ipid uint16, groupSize int, timeDelta time.Duration) float64 {
	// Base confidence
	confidence := 0.6
	
	// Boost for multiple observations
	if groupSize > 2 {
		confidence += 0.1 * float64(groupSize-2)
	}
	
	// Penalty for long time delta
	if timeDelta > time.Second {
		confidence -= 0.1 * float64(timeDelta.Seconds())
	}
	
	// Penalty for common IP IDs (0, 1, etc.)
	if ipid < 100 {
		confidence -= 0.2
	}
	
	// Cap confidence
	if confidence > 0.95 {
		confidence = 0.95
	}
	if confidence < 0.1 {
		confidence = 0.1
	}
	
	return confidence
}

// PayloadHashStrategy correlates packets based on payload content
type PayloadHashStrategy struct {
	config *NPointConfig
}

func (s *PayloadHashStrategy) Name() string {
	return "Payload Hash Correlation"
}

func (s *PayloadHashStrategy) Correlate(observations []PacketObservation) []CorrelationMatch {
	var matches []CorrelationMatch
	
	// Group by payload hash
	hashGroups := make(map[string][]PacketObservation)
	for _, obs := range observations {
		if obs.Packet.PayloadHash != "" {
			hashGroups[obs.Packet.PayloadHash] = append(hashGroups[obs.Packet.PayloadHash], obs)
		}
	}
	
	// Find matches
	for _, group := range hashGroups {
		if len(group) < 2 {
			continue
		}
		
		// Sort by timestamp
		sort.Slice(group, func(i, j int) bool {
			return group[i].Timestamp.Before(group[j].Timestamp)
		})
		
		// Check time delta
		timeDelta := group[len(group)-1].Timestamp.Sub(group[0].Timestamp)
		if timeDelta > s.config.MaxTimeDelta {
			continue
		}
		
		// Collect unique points and flows
		points := make(map[string]bool)
		flows := make(map[types.FlowKey]bool)
		for _, obs := range group {
			points[obs.PointID] = true
			flows[obs.FlowKey] = true
		}
		
		if len(points) < 2 {
			continue
		}
		
		// Create match for each flow
		for flow := range flows {
			var pointList []string
			for p := range points {
				pointList = append(pointList, p)
			}
			
			matches = append(matches, CorrelationMatch{
				FlowKey:     flow,
				Points:      pointList,
				MatchType:   "payload",
				Confidence:  0.9, // High confidence for payload matches
				Latency:     timeDelta,
				PacketCount: len(group),
			})
		}
	}
	
	return matches
}

// TCPSeqStrategy correlates TCP packets based on sequence numbers
type TCPSeqStrategy struct {
	config *NPointConfig
}

func (s *TCPSeqStrategy) Name() string {
	return "TCP Sequence Correlation"
}

func (s *TCPSeqStrategy) Correlate(observations []PacketObservation) []CorrelationMatch {
	var matches []CorrelationMatch
	
	// Only process TCP packets
	tcpObs := []PacketObservation{}
	for _, obs := range observations {
		if obs.Packet.Protocol == "tcp" && obs.Packet.TCPSeq != 0 {
			tcpObs = append(tcpObs, obs)
		}
	}
	
	// Group by TCP sequence number ranges
	seqGroups := make(map[uint32][]PacketObservation)
	for _, obs := range tcpObs {
		// Group by sequence number (with some tolerance for retransmissions)
		baseSeq := obs.Packet.TCPSeq / 1000 * 1000 // Round to nearest 1000
		seqGroups[baseSeq] = append(seqGroups[baseSeq], obs)
	}
	
	// Find matches
	for _, group := range seqGroups {
		if len(group) < 2 {
			continue
		}
		
		// Group by flow
		flowGroups := make(map[types.FlowKey][]PacketObservation)
		for _, obs := range group {
			flowGroups[obs.FlowKey] = append(flowGroups[obs.FlowKey], obs)
		}
		
		// Check each flow
		for flow, flowObs := range flowGroups {
			if len(flowObs) < 2 {
				continue
			}
			
			// Sort by timestamp
			sort.Slice(flowObs, func(i, j int) bool {
				return flowObs[i].Timestamp.Before(flowObs[j].Timestamp)
			})
			
			// Check time delta
			timeDelta := flowObs[len(flowObs)-1].Timestamp.Sub(flowObs[0].Timestamp)
			if timeDelta > s.config.MaxTimeDelta {
				continue
			}
			
			// Collect unique points
			points := make(map[string]bool)
			for _, obs := range flowObs {
				points[obs.PointID] = true
			}
			
			if len(points) < 2 {
				continue
			}
			
			var pointList []string
			for p := range points {
				pointList = append(pointList, p)
			}
			
			confidence := s.calculateTCPConfidence(flowObs)
			
			matches = append(matches, CorrelationMatch{
				FlowKey:     flow,
				Points:      pointList,
				MatchType:   "tcp_seq",
				Confidence:  confidence,
				Latency:     timeDelta,
				PacketCount: len(flowObs),
			})
		}
	}
	
	return matches
}

func (s *TCPSeqStrategy) calculateTCPConfidence(observations []PacketObservation) float64 {
	// Check sequence number progression
	validProgression := true
	for i := 1; i < len(observations); i++ {
		seqDiff := observations[i].Packet.TCPSeq - observations[i-1].Packet.TCPSeq
		// Allow for reasonable sequence progression (up to 64KB)
		if seqDiff > 65536 {
			validProgression = false
			break
		}
	}
	
	if validProgression {
		return 0.85
	}
	return 0.6
}

// TimingStrategy correlates packets based on timing patterns
type TimingStrategy struct {
	config *NPointConfig
}

func (s *TimingStrategy) Name() string {
	return "Timing Pattern Correlation"
}

func (s *TimingStrategy) Correlate(observations []PacketObservation) []CorrelationMatch {
	var matches []CorrelationMatch
	
	// Group by flow
	flowGroups := make(map[types.FlowKey][]PacketObservation)
	for _, obs := range observations {
		flowGroups[obs.FlowKey] = append(flowGroups[obs.FlowKey], obs)
	}
	
	// Analyze timing patterns for each flow
	for flow, flowObs := range flowGroups {
		if len(flowObs) < 3 { // Need at least 3 packets for pattern
			continue
		}
		
		// Sort by timestamp
		sort.Slice(flowObs, func(i, j int) bool {
			return flowObs[i].Timestamp.Before(flowObs[j].Timestamp)
		})
		
		// Group by capture point
		pointGroups := make(map[string][]PacketObservation)
		for _, obs := range flowObs {
			pointGroups[obs.PointID] = append(pointGroups[obs.PointID], obs)
		}
		
		if len(pointGroups) < 2 {
			continue
		}
		
		// Compare timing patterns between points
		var points []string
		for p := range pointGroups {
			points = append(points, p)
		}
		
		if len(points) < 2 {
			continue
		}
		
		// Calculate inter-packet delays for each point
		point1Delays := s.calculateDelays(pointGroups[points[0]])
		point2Delays := s.calculateDelays(pointGroups[points[1]])
		
		// Compare patterns
		similarity := s.compareDelayPatterns(point1Delays, point2Delays)
		
		if similarity > 0.7 {
			matches = append(matches, CorrelationMatch{
				FlowKey:     flow,
				Points:      points,
				MatchType:   "timing",
				Confidence:  similarity,
				Latency:     flowObs[len(flowObs)-1].Timestamp.Sub(flowObs[0].Timestamp),
				PacketCount: len(flowObs),
			})
		}
	}
	
	return matches
}

func (s *TimingStrategy) calculateDelays(observations []PacketObservation) []time.Duration {
	if len(observations) < 2 {
		return nil
	}
	
	delays := make([]time.Duration, len(observations)-1)
	for i := 1; i < len(observations); i++ {
		delays[i-1] = observations[i].Timestamp.Sub(observations[i-1].Timestamp)
	}
	
	return delays
}

func (s *TimingStrategy) compareDelayPatterns(delays1, delays2 []time.Duration) float64 {
	if len(delays1) == 0 || len(delays2) == 0 {
		return 0
	}
	
	// Use the shorter length
	minLen := len(delays1)
	if len(delays2) < minLen {
		minLen = len(delays2)
	}
	
	// Calculate correlation coefficient
	var sum1, sum2, sumProd float64
	var sqSum1, sqSum2 float64
	
	for i := 0; i < minLen; i++ {
		v1 := float64(delays1[i].Microseconds())
		v2 := float64(delays2[i].Microseconds())
		
		sum1 += v1
		sum2 += v2
		sumProd += v1 * v2
		sqSum1 += v1 * v1
		sqSum2 += v2 * v2
	}
	
	n := float64(minLen)
	numerator := n*sumProd - sum1*sum2
	denominator := math.Sqrt((n*sqSum1 - sum1*sum1) * (n*sqSum2 - sum2*sum2))
	
	if denominator == 0 {
		return 0
	}
	
	correlation := numerator / denominator
	
	// Convert to confidence (0 to 1)
	if correlation < 0 {
		correlation = 0
	}
	
	return correlation
}