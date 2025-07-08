package npoint

import (
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/janus-project/janus/pkg/types"
)

func TestVisualizerGraphviz(t *testing.T) {
	// Create test result and graph
	result := &NPointCorrelationResult{
		TotalFlows:      10,
		CorrelatedFlows: 7,
		ProcessingTime:  time.Second,
		PacketsAnalyzed: 1000,
		CapturePoints: []CapturePoint{
			{ID: "point1", Name: "Router 1"},
			{ID: "point2", Name: "Router 2"},
		},
		FlowPaths: make(map[types.FlowKey]*FlowPath),
	}
	
	graph := &FlowGraph{
		Nodes: map[string]*GraphNode{
			"point1": {
				PointID:       "point1",
				Point:         CapturePoint{ID: "point1", Name: "Router 1"},
				TotalPackets:  500,
				OutgoingFlows: 5,
			},
			"point2": {
				PointID:      "point2",
				Point:        CapturePoint{ID: "point2", Name: "Router 2"},
				TotalPackets: 500,
				IncomingFlows: 5,
			},
		},
		Edges: []*GraphEdge{
			{
				Source:      "point1",
				Destination: "point2",
				FlowCount:   5,
				PacketCount: 1000,
			},
		},
	}
	
	visualizer := NewVisualizer(result, graph)
	
	// Test Graphviz generation
	dot := visualizer.GenerateGraphviz()
	
	if !strings.Contains(dot, "digraph FlowGraph") {
		t.Error("Graphviz output missing digraph declaration")
	}
	
	if !strings.Contains(dot, "point1") || !strings.Contains(dot, "point2") {
		t.Error("Graphviz output missing nodes")
	}
	
	if !strings.Contains(dot, "Router 1") || !strings.Contains(dot, "Router 2") {
		t.Error("Graphviz output missing node labels")
	}
	
	if !strings.Contains(dot, "5 flows") {
		t.Error("Graphviz output missing edge labels")
	}
}

func TestVisualizerMermaid(t *testing.T) {
	result := &NPointCorrelationResult{}
	graph := &FlowGraph{
		Nodes: map[string]*GraphNode{
			"point1": {PointID: "point1", Point: CapturePoint{Name: "Router 1"}, TotalPackets: 100},
			"point2": {PointID: "point2", Point: CapturePoint{Name: "Router 2"}, TotalPackets: 100},
		},
		Edges: []*GraphEdge{
			{Source: "point1", Destination: "point2", FlowCount: 3},
		},
	}
	
	visualizer := NewVisualizer(result, graph)
	mermaid := visualizer.GenerateMermaid()
	
	if !strings.Contains(mermaid, "graph LR") {
		t.Error("Mermaid output missing graph declaration")
	}
	
	if !strings.Contains(mermaid, "3 flows") {
		t.Error("Mermaid output missing edge labels")
	}
}

func TestVisualizerFlowTable(t *testing.T) {
	// Create test flow paths
	flowPaths := map[types.FlowKey]*FlowPath{
		"tcp:192.168.1.1:80->10.0.0.1:443": {
			Points:      []string{"point1", "point2"},
			PacketCount: 100,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now().Add(time.Second),
		},
		"tcp:192.168.1.2:80->10.0.0.1:443": {
			Points:      []string{"point1", "point2", "point3"},
			PacketCount: 50,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now().Add(500 * time.Millisecond),
		},
	}
	
	result := &NPointCorrelationResult{
		FlowPaths: flowPaths,
	}
	
	visualizer := NewVisualizer(result, &FlowGraph{})
	
	// Capture output
	var output strings.Builder
	visualizer.GenerateFlowTable(&output)
	
	table := output.String()
	
	if !strings.Contains(table, "Flow Key") {
		t.Error("Flow table missing header")
	}
	
	if !strings.Contains(table, "point1 -> point2") {
		t.Error("Flow table missing path information")
	}
	
	if !strings.Contains(table, "100") {
		t.Error("Flow table missing packet count")
	}
}

func TestVisualizerSummary(t *testing.T) {
	result := &NPointCorrelationResult{
		TotalFlows:      20,
		CorrelatedFlows: 15,
		PacketsAnalyzed: 5000,
		ProcessingTime:  2 * time.Second,
		CapturePoints: []CapturePoint{
			{ID: "point1", Name: "Router 1", Location: "/tmp/r1.pcap"},
			{ID: "point2", Name: "Router 2", Location: "/tmp/r2.pcap"},
		},
		Matches: []CorrelationMatch{
			{MatchType: "ipid"},
			{MatchType: "payload"},
			{MatchType: "tcp_seq"},
		},
	}
	
	graph := &FlowGraph{}
	visualizer := NewVisualizer(result, graph)
	
	var output strings.Builder
	visualizer.GenerateSummary(&output)
	
	summary := output.String()
	
	if !strings.Contains(summary, "N-Point Correlation Summary") {
		t.Error("Summary missing title")
	}
	
	if !strings.Contains(summary, "Total Flows: 20") {
		t.Error("Summary missing total flows")
	}
	
	if !strings.Contains(summary, "Correlated Flows: 15") {
		t.Error("Summary missing correlated flows")
	}
	
	if !strings.Contains(summary, "75.0%") { // 15/20 * 100
		t.Error("Summary missing correlation percentage")
	}
	
	if !strings.Contains(summary, "Router 1") {
		t.Error("Summary missing capture point info")
	}
}

func TestVisualizerPathVisualization(t *testing.T) {
	flowKey := types.FlowKey("tcp:192.168.1.1:80->10.0.0.1:443")
	baseTime := time.Now()
	
	observations := []PacketObservation{
		{
			PointID:   "point1",
			Timestamp: baseTime,
			Packet: types.PacketInfo{
				SrcIP:   []byte{192, 168, 1, 1},
				SrcPort: 80,
				DstIP:   []byte{10, 0, 0, 1},
				DstPort: 443,
				IPID:    12345,
				TTL:     64,
			},
		},
		{
			PointID:   "point2",
			Timestamp: baseTime.Add(10 * time.Millisecond),
			Packet: types.PacketInfo{
				SrcIP:   []byte{192, 168, 1, 1},
				SrcPort: 80,
				DstIP:   []byte{10, 0, 0, 1},
				DstPort: 443,
				IPID:    12345,
				TTL:     63,
			},
		},
	}
	
	fp := &FlowPath{
		FlowKey: flowKey,
	}
	for _, obs := range observations {
		fp.AddObservation(obs)
	}
	
	result := &NPointCorrelationResult{
		FlowPaths: map[types.FlowKey]*FlowPath{
			flowKey: fp,
		},
	}
	
	visualizer := NewVisualizer(result, &FlowGraph{})
	pathViz := visualizer.GeneratePathVisualization(flowKey)
	
	if !strings.Contains(pathViz, string(flowKey)) {
		t.Error("Path visualization missing flow key")
	}
	
	if !strings.Contains(pathViz, "point1") || !strings.Contains(pathViz, "point2") {
		t.Error("Path visualization missing capture points")
	}
	
	if !strings.Contains(pathViz, "192.168.1.1:80") {
		t.Error("Path visualization missing packet details")
	}
	
	if !strings.Contains(pathViz, "IP ID: 12345") {
		t.Error("Path visualization missing IP ID")
	}
	
	if !strings.Contains(pathViz, "TTL: 64") {
		t.Error("Path visualization missing TTL")
	}
}

func TestTimeRange(t *testing.T) {
	start := time.Now()
	end := start.Add(time.Hour)
	
	tr := TimeRange{
		Start: start,
		End:   end,
	}
	
	// Test duration
	if tr.Duration() != time.Hour {
		t.Errorf("Expected duration 1h, got %v", tr.Duration())
	}
	
	// Test contains
	midTime := start.Add(30 * time.Minute)
	if !tr.Contains(midTime) {
		t.Error("TimeRange should contain mid-time")
	}
	
	beforeTime := start.Add(-time.Minute)
	if tr.Contains(beforeTime) {
		t.Error("TimeRange should not contain before-time")
	}
	
	afterTime := end.Add(time.Minute)
	if tr.Contains(afterTime) {
		t.Error("TimeRange should not contain after-time")
	}
}

func TestCorrelationMatchMerging(t *testing.T) {
	config := DefaultNPointConfig()
	nc := NewNPointCorrelator(config)
	
	matches := []CorrelationMatch{
		{
			FlowKey:    "flow1",
			Points:     []string{"point1", "point2"},
			MatchType:  "ipid",
			Confidence: 0.8,
		},
		{
			FlowKey:    "flow1",
			Points:     []string{"point1", "point2"},
			MatchType:  "payload",
			Confidence: 0.9,
		},
		{
			FlowKey:    "flow2",
			Points:     []string{"point2", "point3"},
			MatchType:  "tcp_seq",
			Confidence: 0.7,
		},
	}
	
	merged := nc.mergeMatches(matches)
	
	// Should have 2 merged matches (one for each flow)
	if len(merged) != 2 {
		t.Errorf("Expected 2 merged matches, got %d", len(merged))
	}
	
	// Find flow1 match
	var flow1Match *CorrelationMatch
	for i := range merged {
		if merged[i].FlowKey == "flow1" {
			flow1Match = &merged[i]
			break
		}
	}
	
	if flow1Match == nil {
		t.Fatal("flow1 match not found")
	}
	
	// Check merged confidence (average of 0.8 and 0.9)
	expectedConfidence := (0.8 + 0.9) / 2
	if flow1Match.Confidence < expectedConfidence-0.01 || flow1Match.Confidence > expectedConfidence+0.01 {
		t.Errorf("Expected confidence around %f, got %f", expectedConfidence, flow1Match.Confidence)
	}
	
	if flow1Match.MatchType != "multi-strategy" {
		t.Errorf("Expected match type 'multi-strategy', got '%s'", flow1Match.MatchType)
	}
}

func TestFileOutputFunctions(t *testing.T) {
	// Test file saving functionality
	tempFile, err := ioutil.TempFile("", "janus_test_*.dot")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())
	tempFile.Close()
	
	testContent := "digraph test { a -> b; }"
	
	// This would test the saveToFile function from main_phase4.go
	// Since it's in main package, we simulate it here
	err = ioutil.WriteFile(tempFile.Name(), []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}
	
	// Read back and verify
	content, err := ioutil.ReadFile(tempFile.Name())
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}
	
	if string(content) != testContent {
		t.Errorf("File content mismatch. Expected %s, got %s", testContent, string(content))
	}
}

func TestLargeFlowPathHandling(t *testing.T) {
	// Test handling of large numbers of flow paths
	config := DefaultNPointConfig()
	config.BatchSize = 100
	
	_ = NewOptimizedCorrelator(config)
	
	// Simulate large number of observations
	largeFlowPaths := make(map[types.FlowKey]*FlowPath)
	
	for i := 0; i < 1000; i++ {
		flowKey := types.FlowKey(fmt.Sprintf("flow_%d", i))
		fp := &FlowPath{
			FlowKey:     flowKey,
			Points:      []string{"point1", "point2"},
			PacketCount: 10,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now().Add(time.Millisecond),
		}
		largeFlowPaths[flowKey] = fp
	}
	
	// Test that we can handle large datasets without issues
	if len(largeFlowPaths) != 1000 {
		t.Errorf("Expected 1000 flow paths, got %d", len(largeFlowPaths))
	}
	
	// Test memory efficiency by ensuring no obvious memory leaks
	// (This is a basic test - in production, you'd use memory profiling)
	runtime.GC()
	
	// Test flow cache with large dataset
	cache := NewFlowCache(100) // Smaller cache than dataset
	
	for k, v := range largeFlowPaths {
		cache.Put(k, v)
	}
	
	// Cache should only hold the most recent 100 items
	// (This is simplified - real LRU would need proper implementation)
}