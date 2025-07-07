package nat

import (
	"fmt"
	"io"
	"net"
	"sort"
	"text/tabwriter"
	"time"
)

// Reporter generates human-readable reports for NAT analysis
type Reporter struct {
	detector    *Detector
	transformer *Transformer
	tracker     *ConnectionTracker
}

// NewReporter creates a new NAT analysis reporter
func NewReporter(detector *Detector, transformer *Transformer, tracker *ConnectionTracker) *Reporter {
	return &Reporter{
		detector:    detector,
		transformer: transformer,
		tracker:     tracker,
	}
}

// GenerateReport creates a comprehensive NAT analysis report
func (r *Reporter) GenerateReport(w io.Writer) error {
	fmt.Fprintf(w, "\n═══════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, "              NAT ANALYSIS REPORT (Phase 3)\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════\n\n")
	
	// Executive Summary
	if err := r.writeExecutiveSummary(w); err != nil {
		return err
	}
	
	// NAT Detection Results
	if err := r.writeNATDetectionResults(w); err != nil {
		return err
	}
	
	// Connection Tracking Analysis
	if err := r.writeConnectionAnalysis(w); err != nil {
		return err
	}
	
	// NAT Behavior Analysis
	if err := r.writeNATBehaviorAnalysis(w); err != nil {
		return err
	}
	
	// Detailed NAT Entries
	if err := r.writeDetailedNATEntries(w); err != nil {
		return err
	}
	
	// Recommendations
	if err := r.writeRecommendations(w); err != nil {
		return err
	}
	
	return nil
}

// writeExecutiveSummary writes the executive summary section
func (r *Reporter) writeExecutiveSummary(w io.Writer) error {
	result := r.detector.AnalyzeFlows()
	stats := r.tracker.GetStats()
	
	fmt.Fprintf(w, "EXECUTIVE SUMMARY\n")
	fmt.Fprintf(w, "─────────────────\n")
	fmt.Fprintf(w, "Analysis Duration: %v\n", result.AnalysisTime)
	fmt.Fprintf(w, "Total Flows Analyzed: %d\n", result.TotalFlows)
	fmt.Fprintf(w, "NAT-Modified Flows: %d (%.1f%%)\n", 
		result.NATtedFlows, float64(result.NATtedFlows)/float64(result.TotalFlows)*100)
	fmt.Fprintf(w, "Active Connections: %d\n", stats.ActiveConnections)
	fmt.Fprintf(w, "Detection Confidence: %.1f%%\n\n", result.Confidence*100)
	
	// Key findings
	fmt.Fprintf(w, "Key Findings:\n")
	for i, finding := range result.Findings {
		if i >= 5 { // Limit to top 5 findings
			break
		}
		fmt.Fprintf(w, "  • %s\n", finding)
	}
	fmt.Fprintf(w, "\n")
	
	return nil
}

// writeNATDetectionResults writes the NAT detection results section
func (r *Reporter) writeNATDetectionResults(w io.Writer) error {
	result := r.detector.AnalyzeFlows()
	
	fmt.Fprintf(w, "NAT DETECTION RESULTS\n")
	fmt.Fprintf(w, "────────────────────\n")
	
	// NAT type distribution
	typeCount := make(map[TransformationType]int)
	for _, entry := range result.DetectedNATs {
		typeCount[entry.TransformType]++
	}
	
	// Sort by count
	types := make([]TransformationType, 0, len(typeCount))
	for t := range typeCount {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool {
		return typeCount[types[i]] > typeCount[types[j]]
	})
	
	// Create table
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "NAT Type\tCount\tPercentage\n")
	fmt.Fprintf(tw, "────────\t─────\t──────────\n")
	
	for _, natType := range types {
		count := typeCount[natType]
		percentage := float64(count) / float64(result.NATtedFlows) * 100
		fmt.Fprintf(tw, "%s\t%d\t%.1f%%\n", natType, count, percentage)
	}
	tw.Flush()
	fmt.Fprintf(w, "\n")
	
	// Double NAT and CGNAT warnings
	if result.DoubleNATFlows > 0 {
		fmt.Fprintf(w, "⚠️  Double NAT detected in %d flows\n", result.DoubleNATFlows)
	}
	if typeCount[CGNAT] > 0 {
		fmt.Fprintf(w, "⚠️  Carrier-Grade NAT (CGNAT) detected in %d flows\n", typeCount[CGNAT])
	}
	fmt.Fprintf(w, "\n")
	
	return nil
}

// writeConnectionAnalysis writes the connection tracking analysis
func (r *Reporter) writeConnectionAnalysis(w io.Writer) error {
	stats := r.tracker.GetStats()
	
	fmt.Fprintf(w, "CONNECTION TRACKING ANALYSIS\n")
	fmt.Fprintf(w, "───────────────────────────\n")
	
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "Metric\tValue\n")
	fmt.Fprintf(tw, "──────\t─────\n")
	fmt.Fprintf(tw, "Total Connections\t%d\n", stats.TotalConnections)
	fmt.Fprintf(tw, "Active Connections\t%d\n", stats.ActiveConnections)
	fmt.Fprintf(tw, "Expired Connections\t%d\n", stats.ExpiredConnections)
	fmt.Fprintf(tw, "TCP Connections\t%d\n", stats.TCPConnections)
	fmt.Fprintf(tw, "UDP Connections\t%d\n", stats.UDPConnections)
	fmt.Fprintf(tw, "Symmetric NAT Flows\t%d\n", stats.SymmetricNATFlows)
	fmt.Fprintf(tw, "Asymmetric NAT Flows\t%d\n", stats.AsymmetricNATFlows)
	tw.Flush()
	fmt.Fprintf(w, "\n")
	
	return nil
}

// writeNATBehaviorAnalysis writes the NAT behavior analysis
func (r *Reporter) writeNATBehaviorAnalysis(w io.Writer) error {
	analysis := r.tracker.AnalyzeNATBehavior()
	
	fmt.Fprintf(w, "NAT BEHAVIOR ANALYSIS\n")
	fmt.Fprintf(w, "────────────────────\n")
	
	// Behavior characteristics
	fmt.Fprintf(w, "Behavior Characteristics:\n")
	if analysis.TotalConnections > 0 {
		portPreservationRate := float64(analysis.PortPreservation) / float64(analysis.TotalConnections) * 100
		fmt.Fprintf(w, "  • Port Preservation Rate: %.1f%%\n", portPreservationRate)
		
		symmetricRate := float64(analysis.SymmetricBehavior) / float64(analysis.TotalConnections) * 100
		fmt.Fprintf(w, "  • Symmetric Traffic Rate: %.1f%%\n", symmetricRate)
	}
	fmt.Fprintf(w, "  • Average Connection Duration: %v\n", analysis.AverageConnectionDur)
	fmt.Fprintf(w, "\n")
	
	// Behavior findings
	if len(analysis.Findings) > 0 {
		fmt.Fprintf(w, "Behavioral Insights:\n")
		for _, finding := range analysis.Findings {
			fmt.Fprintf(w, "  • %s\n", finding)
		}
		fmt.Fprintf(w, "\n")
	}
	
	return nil
}

// writeDetailedNATEntries writes detailed NAT entry information
func (r *Reporter) writeDetailedNATEntries(w io.Writer) error {
	result := r.detector.AnalyzeFlows()
	
	fmt.Fprintf(w, "DETAILED NAT ENTRIES (Top 10)\n")
	fmt.Fprintf(w, "────────────────────────────\n")
	
	// Sort by packet count
	entries := make([]NATEntry, len(result.DetectedNATs))
	copy(entries, result.DetectedNATs)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].PacketCount > entries[j].PacketCount
	})
	
	// Show top 10
	limit := 10
	if len(entries) < limit {
		limit = len(entries)
	}
	
	for i := 0; i < limit; i++ {
		entry := entries[i]
		fmt.Fprintf(w, "\n[Entry %d]\n", i+1)
		fmt.Fprintf(w, "  Type: %s\n", entry.TransformType)
		fmt.Fprintf(w, "  Original:   %s:%d → %s:%d\n", 
			entry.OriginalSrcIP, entry.OriginalSrcPort,
			entry.OriginalDstIP, entry.OriginalDstPort)
		fmt.Fprintf(w, "  Translated: %s:%d → %s:%d\n",
			entry.TranslatedSrcIP, entry.TranslatedSrcPort,
			entry.TranslatedDstIP, entry.TranslatedDstPort)
		fmt.Fprintf(w, "  Protocol: %s\n", entry.Protocol)
		fmt.Fprintf(w, "  Packets: %d\n", entry.PacketCount)
		fmt.Fprintf(w, "  Duration: %v\n", entry.LastSeen.Sub(entry.FirstSeen))
		fmt.Fprintf(w, "  Confidence: %.1f%%\n", entry.Confidence*100)
	}
	
	if len(entries) > limit {
		fmt.Fprintf(w, "\n... and %d more entries\n", len(entries)-limit)
	}
	fmt.Fprintf(w, "\n")
	
	return nil
}

// writeRecommendations writes recommendations based on the analysis
func (r *Reporter) writeRecommendations(w io.Writer) error {
	result := r.detector.AnalyzeFlows()
	behavior := r.tracker.AnalyzeNATBehavior()
	
	fmt.Fprintf(w, "RECOMMENDATIONS\n")
	fmt.Fprintf(w, "──────────────\n")
	
	recommendations := r.generateRecommendations(result, behavior)
	
	for i, rec := range recommendations {
		fmt.Fprintf(w, "%d. %s\n", i+1, rec)
	}
	fmt.Fprintf(w, "\n")
	
	return nil
}

// generateRecommendations creates recommendations based on analysis
func (r *Reporter) generateRecommendations(result *NATDetectionResult, behavior *NATBehaviorAnalysis) []string {
	recs := []string{}
	
	// Double NAT recommendations
	if result.DoubleNATFlows > 0 {
		recs = append(recs, 
			"Double NAT detected - consider simplifying network topology to improve performance",
			"Review routing configuration to eliminate unnecessary NAT layers")
	}
	
	// CGNAT recommendations
	typeCount := make(map[TransformationType]int)
	for _, entry := range result.DetectedNATs {
		typeCount[entry.TransformType]++
	}
	
	if typeCount[CGNAT] > 0 {
		recs = append(recs,
			"CGNAT detected - be aware of potential port exhaustion issues",
			"Consider implementing IPv6 to avoid CGNAT limitations")
	}
	
	// Port preservation recommendations
	if behavior.TotalConnections > 0 {
		portPreservationRate := float64(behavior.PortPreservation) / float64(behavior.TotalConnections) * 100
		if portPreservationRate < 50 {
			recs = append(recs,
				"Low port preservation rate detected - may cause issues with certain applications",
				"Consider configuring NAT for endpoint-independent mapping if possible")
		}
	}
	
	// Connection duration recommendations
	if behavior.AverageConnectionDur < 30*time.Second {
		recs = append(recs,
			"Short connection durations detected - check NAT timeout settings",
			"Increase UDP and TCP timeouts to prevent premature connection drops")
	}
	
	// General recommendations
	if result.Confidence < 0.8 {
		recs = append(recs,
			"Detection confidence is moderate - ensure time synchronization between capture points",
			"Consider capturing at additional network points for better visibility")
	}
	
	return recs
}

// GenerateJSON generates a JSON report of NAT analysis
func (r *Reporter) GenerateJSON() (string, error) {
	// This would generate a structured JSON report
	// Implementation omitted for brevity
	return "{}", nil
}

// GenerateGraphviz generates a Graphviz representation of NAT flows
func (r *Reporter) GenerateGraphviz(w io.Writer) error {
	result := r.detector.AnalyzeFlows()
	
	fmt.Fprintf(w, "digraph NAT {\n")
	fmt.Fprintf(w, "  rankdir=LR;\n")
	fmt.Fprintf(w, "  node [shape=box];\n\n")
	
	// Create nodes for unique IPs
	ips := make(map[string]bool)
	for _, entry := range result.DetectedNATs {
		ips[entry.OriginalSrcIP.String()] = true
		ips[entry.TranslatedSrcIP.String()] = true
		ips[entry.OriginalDstIP.String()] = true
		ips[entry.TranslatedDstIP.String()] = true
	}
	
	// Define nodes
	for ip := range ips {
		label := ip
		if isPrivateIP(parseIP(ip)) {
			label += "\\n(Private)"
		}
		fmt.Fprintf(w, "  \"%s\" [label=\"%s\"];\n", ip, label)
	}
	
	fmt.Fprintf(w, "\n")
	
	// Create edges for NAT transformations
	for i, entry := range result.DetectedNATs {
		if i > 20 { // Limit to prevent overly complex graphs
			break
		}
		
		// Original flow
		fmt.Fprintf(w, "  \"%s\" -> \"%s\" [label=\"%s:%d->%d\", color=blue];\n",
			entry.OriginalSrcIP, entry.OriginalDstIP,
			entry.Protocol, entry.OriginalSrcPort, entry.OriginalDstPort)
		
		// Translated flow
		fmt.Fprintf(w, "  \"%s\" -> \"%s\" [label=\"%s:%d->%d\", color=red, style=dashed];\n",
			entry.TranslatedSrcIP, entry.TranslatedDstIP,
			entry.Protocol, entry.TranslatedSrcPort, entry.TranslatedDstPort)
		
		// NAT transformation
		if !entry.OriginalSrcIP.Equal(entry.TranslatedSrcIP) {
			fmt.Fprintf(w, "  \"%s\" -> \"%s\" [label=\"NAT\", color=green, style=dotted];\n",
				entry.OriginalSrcIP, entry.TranslatedSrcIP)
		}
	}
	
	fmt.Fprintf(w, "}\n")
	
	return nil
}

// Helper function to parse IP string
func parseIP(s string) net.IP {
	return net.ParseIP(s)
}