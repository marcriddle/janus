package npoint

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/janus-project/janus/pkg/types"
)

// Visualizer handles visualization of N-point correlation results
type Visualizer struct {
	result *NPointCorrelationResult
	graph  *FlowGraph
}

// NewVisualizer creates a new visualizer
func NewVisualizer(result *NPointCorrelationResult, graph *FlowGraph) *Visualizer {
	return &Visualizer{
		result: result,
		graph:  graph,
	}
}

// GenerateGraphviz creates a Graphviz DOT representation of the flow graph
func (v *Visualizer) GenerateGraphviz() string {
	var sb strings.Builder
	
	sb.WriteString("digraph FlowGraph {\n")
	sb.WriteString("  rankdir=LR;\n")
	sb.WriteString("  node [shape=box, style=rounded];\n")
	sb.WriteString("  \n")
	
	// Add nodes
	sb.WriteString("  // Capture Points\n")
	for _, node := range v.graph.Nodes {
		label := fmt.Sprintf("%s\\n%d packets\\nIn: %d, Out: %d",
			node.Point.Name,
			node.TotalPackets,
			node.IncomingFlows,
			node.OutgoingFlows)
		sb.WriteString(fmt.Sprintf("  \"%s\" [label=\"%s\"];\n", node.PointID, label))
	}
	sb.WriteString("  \n")
	
	// Add edges
	sb.WriteString("  // Flow Paths\n")
	for _, edge := range v.graph.Edges {
		label := fmt.Sprintf("%d flows\\n%d packets",
			edge.FlowCount,
			edge.PacketCount)
		
		// Use thicker edges for higher traffic
		penwidth := 1
		if edge.FlowCount > 10 {
			penwidth = 2
		}
		if edge.FlowCount > 50 {
			penwidth = 3
		}
		
		sb.WriteString(fmt.Sprintf("  \"%s\" -> \"%s\" [label=\"%s\", penwidth=%d];\n",
			edge.Source, edge.Destination, label, penwidth))
	}
	
	sb.WriteString("}\n")
	
	return sb.String()
}

// GenerateMermaid creates a Mermaid diagram representation
func (v *Visualizer) GenerateMermaid() string {
	var sb strings.Builder
	
	sb.WriteString("graph LR\n")
	
	// Add nodes
	for _, node := range v.graph.Nodes {
		label := fmt.Sprintf("%s<br/>%d packets",
			node.Point.Name,
			node.TotalPackets)
		sb.WriteString(fmt.Sprintf("    %s[\"%s\"]\n", node.PointID, label))
	}
	
	sb.WriteString("\n")
	
	// Add edges
	for _, edge := range v.graph.Edges {
		label := fmt.Sprintf("%d flows", edge.FlowCount)
		sb.WriteString(fmt.Sprintf("    %s -->|%s| %s\n",
			edge.Source, label, edge.Destination))
	}
	
	return sb.String()
}

// GenerateFlowTable creates a tabular view of flow paths
func (v *Visualizer) GenerateFlowTable(w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	
	fmt.Fprintln(tw, "Flow Key\tPath\tPackets\tLatency\tFirst Seen\tLast Seen")
	fmt.Fprintln(tw, "--------\t----\t-------\t-------\t----------\t---------")
	
	// Sort flows by packet count
	type flowEntry struct {
		key  types.FlowKey
		path *FlowPath
	}
	
	var flows []flowEntry
	for k, p := range v.result.FlowPaths {
		flows = append(flows, flowEntry{k, p})
	}
	
	sort.Slice(flows, func(i, j int) bool {
		return flows[i].path.PacketCount > flows[j].path.PacketCount
	})
	
	// Display top flows
	maxFlows := 20
	if len(flows) < maxFlows {
		maxFlows = len(flows)
	}
	
	for i := 0; i < maxFlows; i++ {
		f := flows[i]
		path := strings.Join(f.path.Points, " -> ")
		
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\n",
			truncateString(string(f.key), 40),
			path,
			f.path.PacketCount,
			f.path.GetLatency(),
			f.path.FirstSeen.Format("15:04:05.000"),
			f.path.LastSeen.Format("15:04:05.000"))
	}
	
	tw.Flush()
	
	if len(flows) > maxFlows {
		fmt.Fprintf(w, "\n... and %d more flows\n", len(flows)-maxFlows)
	}
}

// GenerateSummary creates a summary report
func (v *Visualizer) GenerateSummary(w io.Writer) {
	fmt.Fprintln(w, "=== N-Point Correlation Summary ===")
	fmt.Fprintln(w)
	
	// Basic statistics
	fmt.Fprintf(w, "Total Flows: %d\n", v.result.TotalFlows)
	fmt.Fprintf(w, "Correlated Flows: %d (%.1f%%)\n",
		v.result.CorrelatedFlows,
		float64(v.result.CorrelatedFlows)/float64(v.result.TotalFlows)*100)
	fmt.Fprintf(w, "Packets Analyzed: %d\n", v.result.PacketsAnalyzed)
	fmt.Fprintf(w, "Processing Time: %s\n", v.result.ProcessingTime)
	fmt.Fprintln(w)
	
	// Capture points
	fmt.Fprintf(w, "Capture Points (%d):\n", len(v.result.CapturePoints))
	for _, cp := range v.result.CapturePoints {
		fmt.Fprintf(w, "  - %s (%s): %s\n", cp.ID, cp.Name, cp.Location)
	}
	fmt.Fprintln(w)
	
	// Top paths
	fmt.Fprintln(w, "Most Common Flow Paths:")
	topPaths := v.graph.GetTopPaths(5)
	for i, path := range topPaths {
		fmt.Fprintf(w, "  %d. %s\n", i+1, strings.Join(path, " -> "))
	}
	fmt.Fprintln(w)
	
	// Match type distribution
	matchTypes := make(map[string]int)
	for _, match := range v.result.Matches {
		matchTypes[match.MatchType]++
	}
	
	fmt.Fprintln(w, "Correlation Methods Used:")
	for mtype, count := range matchTypes {
		fmt.Fprintf(w, "  - %s: %d matches\n", mtype, count)
	}
}

// GeneratePathVisualization creates an ASCII visualization of a specific flow path
func (v *Visualizer) GeneratePathVisualization(flowKey types.FlowKey) string {
	path, exists := v.result.FlowPaths[flowKey]
	if !exists {
		return "Flow not found"
	}
	
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Flow Path: %s\n", flowKey))
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")
	
	observations := path.GetObservations()
	for i, obs := range observations {
		// Calculate time since first observation
		timeSinceFirst := obs.Timestamp.Sub(observations[0].Timestamp)
		
		// Create visualization
		indent := strings.Repeat(" ", i*4)
		sb.WriteString(fmt.Sprintf("%s[%s] %s\n",
			indent,
			obs.PointID,
			obs.Timestamp.Format("15:04:05.000")))
		
		if i > 0 {
			latency := obs.Timestamp.Sub(observations[i-1].Timestamp)
			sb.WriteString(fmt.Sprintf("%s  └─> +%s (total: %s)\n",
				indent,
				latency,
				timeSinceFirst))
		}
		
		// Show packet details
		sb.WriteString(fmt.Sprintf("%s      %s:%d -> %s:%d\n",
			indent,
			obs.Packet.SrcIP,
			obs.Packet.SrcPort,
			obs.Packet.DstIP,
			obs.Packet.DstPort))
		
		if obs.Packet.IPID != 0 {
			sb.WriteString(fmt.Sprintf("%s      IP ID: %d, TTL: %d\n",
				indent,
				obs.Packet.IPID,
				obs.Packet.TTL))
		}
		
		sb.WriteString("\n")
	}
	
	return sb.String()
}

// truncateString truncates a string to the specified length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}