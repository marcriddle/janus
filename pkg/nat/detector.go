package nat

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/janus-project/janus/pkg/types"
)

// Detector implements advanced NAT detection and tracking
type Detector struct {
	// NAT entries indexed by original flow
	natTable map[types.FlowKey]*NATEntry
	
	// Connection state tracking
	flowStates map[types.FlowKey]*FlowState
	
	// Reverse mapping for bidirectional flow detection
	reverseTable map[types.FlowKey]types.FlowKey
	
	// NAT chains for multi-hop scenarios
	chains []NATChain
	
	// Configuration
	cfg DetectorConfig
	
	mu sync.RWMutex
}

// DetectorConfig contains configuration for NAT detection
type DetectorConfig struct {
	// Timeout for connection state
	ConnectionTimeout time.Duration
	
	// Enable heuristic detection methods
	EnableHeuristics bool
	
	// Minimum confidence threshold
	MinConfidence float64
	
	// Enable CGNAT detection
	DetectCGNAT bool
	
	// RFC1918 private address ranges
	PrivateRanges []*net.IPNet
}

// DefaultConfig returns a default configuration
func DefaultConfig() DetectorConfig {
	privateRanges := []*net.IPNet{
		{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},      // 10.0.0.0/8
		{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)},    // 172.16.0.0/12
		{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(16, 32)},   // 192.168.0.0/16
		{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)},    // 100.64.0.0/10 (CGNAT)
	}
	
	return DetectorConfig{
		ConnectionTimeout: 5 * time.Minute,
		EnableHeuristics:  true,
		MinConfidence:     0.7,
		DetectCGNAT:       true,
		PrivateRanges:     privateRanges,
	}
}

// NewDetector creates a new NAT detector
func NewDetector(cfg DetectorConfig) *Detector {
	return &Detector{
		natTable:     make(map[types.FlowKey]*NATEntry),
		flowStates:   make(map[types.FlowKey]*FlowState),
		reverseTable: make(map[types.FlowKey]types.FlowKey),
		chains:       []NATChain{},
		cfg:          cfg,
	}
}

// DetectNAT analyzes packet pairs to detect NAT transformations
func (d *Detector) DetectNAT(p1, p2 *types.CapturePointInfo) (*NATEntry, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	// Quick check: if addresses are identical, no NAT
	if d.flowsIdentical(p1, p2) {
		return nil, nil
	}
	
	// Create NAT entry
	entry := &NATEntry{
		OriginalSrcIP:     p1.Packet.SrcIP,
		OriginalSrcPort:   p1.Packet.SrcPort,
		OriginalDstIP:     p1.Packet.DstIP,
		OriginalDstPort:   p1.Packet.DstPort,
		TranslatedSrcIP:   p2.Packet.SrcIP,
		TranslatedSrcPort: p2.Packet.SrcPort,
		TranslatedDstIP:   p2.Packet.DstIP,
		TranslatedDstPort: p2.Packet.DstPort,
		Protocol:          p1.Packet.Protocol,
		FirstSeen:         p1.Packet.Timestamp,
		LastSeen:          p2.Packet.Timestamp,
		PacketCount:       1,
		Confidence:        d.calculateConfidence(p1, p2),
	}
	
	// Determine transformation type
	entry.TransformType = d.classifyTransformation(entry)
	
	// Update tables
	originalFlow := entry.GetOriginalFlow()
	translatedFlow := entry.GetTranslatedFlow()
	
	d.natTable[originalFlow] = entry
	d.reverseTable[translatedFlow] = originalFlow
	
	// Update flow state
	d.updateFlowState(originalFlow, entry, p1.Packet.Timestamp)
	
	return entry, nil
}

// flowsIdentical checks if two packet flows are identical
func (d *Detector) flowsIdentical(p1, p2 *types.CapturePointInfo) bool {
	return p1.Packet.SrcIP.Equal(p2.Packet.SrcIP) &&
		p1.Packet.DstIP.Equal(p2.Packet.DstIP) &&
		p1.Packet.SrcPort == p2.Packet.SrcPort &&
		p1.Packet.DstPort == p2.Packet.DstPort
}

// calculateConfidence calculates the confidence of NAT detection
func (d *Detector) calculateConfidence(p1, p2 *types.CapturePointInfo) float64 {
	confidence := 0.5 // Base confidence
	
	// Higher confidence if one side is private IP
	if d.isPrivateIP(p1.Packet.SrcIP) && !d.isPrivateIP(p2.Packet.SrcIP) {
		confidence += 0.3
	}
	
	// Higher confidence if ports are in typical NAT ranges
	if p2.Packet.SrcPort > 1024 && p2.Packet.SrcPort < 65535 {
		confidence += 0.1
	}
	
	// Lower confidence if both are private (might be routing)
	if d.isPrivateIP(p1.Packet.SrcIP) && d.isPrivateIP(p2.Packet.SrcIP) {
		confidence -= 0.2
	}
	
	// Ensure confidence is between 0 and 1
	if confidence > 1.0 {
		confidence = 1.0
	} else if confidence < 0.0 {
		confidence = 0.0
	}
	
	return confidence
}

// isPrivateIP checks if an IP is in private address space
func (d *Detector) isPrivateIP(ip net.IP) bool {
	for _, privateRange := range d.cfg.PrivateRanges {
		if privateRange.Contains(ip) {
			return true
		}
	}
	return false
}

// classifyTransformation determines the type of NAT transformation
func (d *Detector) classifyTransformation(entry *NATEntry) TransformationType {
	srcChanged := !entry.OriginalSrcIP.Equal(entry.TranslatedSrcIP) || 
		entry.OriginalSrcPort != entry.TranslatedSrcPort
	dstChanged := !entry.OriginalDstIP.Equal(entry.TranslatedDstIP) || 
		entry.OriginalDstPort != entry.TranslatedDstPort
	
	// Check for CGNAT (100.64.0.0/10 range)
	cgnatRange := &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}
	if d.cfg.DetectCGNAT && cgnatRange.Contains(entry.OriginalSrcIP) {
		return CGNAT
	}
	
	// Basic classification
	if srcChanged && !dstChanged {
		return SourceNAT
	} else if !srcChanged && dstChanged {
		return DestinationNAT
	} else if srcChanged && dstChanged {
		return DoubleNAT
	}
	
	return NoTransformation
}

// updateFlowState updates the connection state for a flow
func (d *Detector) updateFlowState(flowKey types.FlowKey, entry *NATEntry, timestamp time.Time) {
	state, exists := d.flowStates[flowKey]
	if !exists {
		state = &FlowState{
			FlowKey:        flowKey,
			State:          StateNew,
			NATEntry:       entry,
			LastPacketTime: timestamp,
		}
		d.flowStates[flowKey] = state
	} else {
		state.LastPacketTime = timestamp
		if state.State == StateNew && state.PacketsSent > 0 && state.PacketsReceived > 0 {
			state.State = StateEstablished
			state.IsSymmetric = true
		}
	}
	
	state.PacketsSent++
}

// DetectNATChains identifies multi-hop NAT scenarios
func (d *Detector) DetectNATChains(packets []*types.CapturePointInfo) []NATChain {
	d.mu.RLock()
	defer d.mu.RUnlock()
	
	chains := []NATChain{}
	
	// Group packets by flow
	flowGroups := make(map[types.FlowKey][]*types.CapturePointInfo)
	for _, pkt := range packets {
		flow := types.NewFlowKey(pkt.Packet.Protocol, pkt.Packet.SrcIP, pkt.Packet.SrcPort,
			pkt.Packet.DstIP, pkt.Packet.DstPort)
		flowGroups[flow] = append(flowGroups[flow], pkt)
	}
	
	// Look for chains by following transformations
	visited := make(map[types.FlowKey]bool)
	for flow, pkts := range flowGroups {
		if visited[flow] || len(pkts) < 2 {
			continue
		}
		
		chain := d.traceNATChain(flow, flowGroups, visited)
		if len(chain.Transformations) > 1 {
			chains = append(chains, chain)
		}
	}
	
	return chains
}

// traceNATChain follows a flow through multiple NAT transformations
func (d *Detector) traceNATChain(startFlow types.FlowKey, flowGroups map[types.FlowKey][]*types.CapturePointInfo, 
	visited map[types.FlowKey]bool) NATChain {
	
	chain := NATChain{
		Transformations: []NATEntry{},
		HopCount:        0,
	}
	
	currentFlow := startFlow
	for {
		visited[currentFlow] = true
		
		// Look for NAT entry for this flow
		if entry, exists := d.natTable[currentFlow]; exists {
			chain.Transformations = append(chain.Transformations, *entry)
			chain.HopCount++
			
			// Follow to next hop
			nextFlow := entry.GetTranslatedFlow()
			if _, exists := flowGroups[nextFlow]; exists && !visited[nextFlow] {
				currentFlow = nextFlow
			} else {
				break
			}
		} else {
			break
		}
	}
	
	// Calculate total latency
	if len(chain.Transformations) > 0 {
		first := chain.Transformations[0].FirstSeen
		last := chain.Transformations[len(chain.Transformations)-1].LastSeen
		chain.TotalLatency = last.Sub(first)
	}
	
	return chain
}

// AnalyzeFlows performs comprehensive NAT analysis on all tracked flows
func (d *Detector) AnalyzeFlows() *NATDetectionResult {
	d.mu.RLock()
	defer d.mu.RUnlock()
	
	startTime := time.Now()
	
	result := &NATDetectionResult{
		DetectedNATs:    make([]NATEntry, 0, len(d.natTable)),
		NATChains:       d.chains,
		FlowStates:      make(map[types.FlowKey]*FlowState),
		DetectionMethod: "Multi-strategy correlation with state tracking",
		TotalFlows:      len(d.flowStates),
		Findings:        []string{},
	}
	
	// Copy NAT entries
	for _, entry := range d.natTable {
		result.DetectedNATs = append(result.DetectedNATs, *entry)
		result.NATtedFlows++
		
		// Check for double NAT
		if entry.TransformType == DoubleNAT {
			result.DoubleNATFlows++
		}
	}
	
	// Copy flow states
	for flow, state := range d.flowStates {
		result.FlowStates[flow] = state
		if state.IsSymmetric {
			result.SymmetricFlows++
		}
	}
	
	// Generate findings
	result.Findings = d.generateFindings(result)
	
	// Calculate overall confidence
	if result.NATtedFlows > 0 {
		totalConfidence := 0.0
		for _, entry := range result.DetectedNATs {
			totalConfidence += entry.Confidence
		}
		result.Confidence = totalConfidence / float64(result.NATtedFlows)
	}
	
	result.AnalysisTime = time.Since(startTime)
	
	return result
}

// generateFindings creates human-readable findings from the analysis
func (d *Detector) generateFindings(result *NATDetectionResult) []string {
	findings := []string{}
	
	// Basic statistics
	findings = append(findings, fmt.Sprintf("Analyzed %d flows, %d (%.1f%%) show NAT transformation",
		result.TotalFlows, result.NATtedFlows, 
		float64(result.NATtedFlows)/float64(result.TotalFlows)*100))
	
	// NAT types distribution
	typeCount := make(map[TransformationType]int)
	for _, entry := range result.DetectedNATs {
		typeCount[entry.TransformType]++
	}
	
	for natType, count := range typeCount {
		findings = append(findings, fmt.Sprintf("%s detected in %d flows", natType, count))
	}
	
	// Double NAT detection
	if result.DoubleNATFlows > 0 {
		findings = append(findings, fmt.Sprintf("Double NAT detected in %d flows - may indicate complex network topology", 
			result.DoubleNATFlows))
	}
	
	// CGNAT detection
	cgnatCount := typeCount[CGNAT]
	if cgnatCount > 0 {
		findings = append(findings, fmt.Sprintf("Carrier-Grade NAT (CGNAT) detected in %d flows - typical of ISP networks",
			cgnatCount))
	}
	
	// Symmetric flow analysis
	if result.TotalFlows > 0 {
		symmetricPct := float64(result.SymmetricFlows) / float64(result.TotalFlows) * 100
		findings = append(findings, fmt.Sprintf("%.1f%% of flows show bidirectional traffic", symmetricPct))
	}
	
	return findings
}

// GetNATEntry returns the NAT entry for a given flow
func (d *Detector) GetNATEntry(flow types.FlowKey) (*NATEntry, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	
	entry, exists := d.natTable[flow]
	return entry, exists
}

// GetFlowState returns the state of a given flow
func (d *Detector) GetFlowState(flow types.FlowKey) (*FlowState, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	
	state, exists := d.flowStates[flow]
	return state, exists
}