// +build phase4

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/janus-project/janus/pkg/npoint"
	"github.com/janus-project/janus/pkg/types"
)

// stringSlice implements flag.Value for string slices
type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	var (
		// N-point correlation flags
		pcapFiles     stringSlice
		pointNames    stringSlice
		outputFormat  = flag.String("format", "table", "Output format: table, json, graphviz, mermaid")
		graphvizFile  = flag.String("graphviz", "", "Save Graphviz DOT file")
		mermaidFile   = flag.String("mermaid", "", "Save Mermaid diagram file")
		
		// Analysis configuration
		maxTimeDelta  = flag.Duration("max-time-delta", 5*time.Second, "Maximum time delta for correlation")
		minConfidence = flag.Float64("min-confidence", 0.7, "Minimum confidence threshold")
		
		// Performance tuning
		workers       = flag.Int("workers", 4, "Number of worker goroutines")
		batchSize     = flag.Int("batch-size", 1000, "Batch size for processing")
		maxMemoryMB   = flag.Int("max-memory", 1024, "Maximum memory usage in MB")
		
		// Correlation methods
		enableIPID        = flag.Bool("enable-ipid", true, "Enable IP ID correlation")
		enablePayload     = flag.Bool("enable-payload", true, "Enable payload hash correlation")
		enableTCPSeq      = flag.Bool("enable-tcp-seq", true, "Enable TCP sequence correlation")
		enableTiming      = flag.Bool("enable-timing", true, "Enable timing pattern correlation")
		
		// Analysis options
		trackBidirectional = flag.Bool("bidirectional", true, "Track bidirectional flows")
		includePartial     = flag.Bool("partial-paths", false, "Include partial flow paths")
		
		// Visualization options
		showTopPaths      = flag.Int("top-paths", 10, "Number of top flow paths to show")
		showFlowDetails   = flag.String("flow-details", "", "Show detailed path for specific flow")
		
		// Legacy support
		verbose = flag.Bool("verbose", false, "Enable verbose output")
		help    = flag.Bool("help", false, "Show help")
	)
	
	flag.Var(&pcapFiles, "pcap", "PCAP file (can be specified multiple times)")
	flag.Var(&pointNames, "point", "Capture point name (can be specified multiple times)")
	
	flag.Parse()
	
	if *help {
		showUsage()
		return
	}
	
	if len(pcapFiles) == 0 {
		fmt.Fprintf(os.Stderr, "Error: At least one PCAP file must be specified\n")
		showUsage()
		os.Exit(1)
	}
	
	// If no point names specified, use filenames
	if len(pointNames) == 0 {
		for _, pcapFile := range pcapFiles {
			basename := filepath.Base(pcapFile)
			name := strings.TrimSuffix(basename, filepath.Ext(basename))
			pointNames = append(pointNames, name)
		}
	}
	
	// Validate arguments
	if len(pcapFiles) != len(pointNames) {
		fmt.Fprintf(os.Stderr, "Error: Number of PCAP files must match number of point names\n")
		os.Exit(1)
	}
	
	if len(pcapFiles) < 2 {
		fmt.Fprintf(os.Stderr, "Error: At least 2 capture points required for N-point correlation\n")
		os.Exit(1)
	}
	
	// Create configuration
	config := &npoint.NPointConfig{
		MaxTimeDelta:      *maxTimeDelta,
		MinConfidence:     *minConfidence,
		EnablePayloadHash: *enablePayload,
		EnableTCPSeq:      *enableTCPSeq,
		EnableIPID:        *enableIPID,
		EnableTiming:      *enableTiming,
		WorkerCount:       *workers,
		BatchSize:         *batchSize,
		MaxMemoryMB:       *maxMemoryMB,
		TrackBidirectional: *trackBidirectional,
		IncludePartialPaths: *includePartial,
	}
	
	// Create correlator
	correlator := npoint.NewOptimizedCorrelator(config)
	
	// Add capture points
	for i, pcapFile := range pcapFiles {
		pointID := fmt.Sprintf("point%d", i+1)
		pointName := pointNames[i]
		
		if *verbose {
			fmt.Printf("Adding capture point: %s (%s) -> %s\n", pointID, pointName, pcapFile)
		}
		
		if err := correlator.AddCapturePoint(pointID, pointName, pcapFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error adding capture point %s: %v\n", pointName, err)
			os.Exit(1)
		}
	}
	
	// Perform correlation
	if *verbose {
		fmt.Printf("Starting N-point correlation analysis...\n")
	}
	
	result, err := correlator.CorrelateOptimized()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error performing correlation: %v\n", err)
		os.Exit(1)
	}
	
	// Create visualizer
	flowGraph := correlator.GetFlowGraph()
	visualizer := npoint.NewVisualizer(result, flowGraph)
	
	// Output results
	switch *outputFormat {
	case "table":
		visualizer.GenerateSummary(os.Stdout)
		fmt.Println()
		
		if *showFlowDetails != "" {
			flowKey := types.FlowKey(*showFlowDetails)
			fmt.Println(visualizer.GeneratePathVisualization(flowKey))
		} else {
			fmt.Println("=== Flow Path Table ===")
			visualizer.GenerateFlowTable(os.Stdout)
		}
		
	case "json":
		// JSON output would be implemented here
		fmt.Println("JSON output not yet implemented")
		
	case "graphviz":
		fmt.Print(visualizer.GenerateGraphviz())
		
	case "mermaid":
		fmt.Print(visualizer.GenerateMermaid())
		
	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown output format '%s'\n", *outputFormat)
		os.Exit(1)
	}
	
	// Save additional outputs
	if *graphvizFile != "" {
		if err := saveToFile(*graphvizFile, visualizer.GenerateGraphviz()); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving Graphviz file: %v\n", err)
		} else if *verbose {
			fmt.Printf("Graphviz diagram saved to: %s\n", *graphvizFile)
		}
	}
	
	if *mermaidFile != "" {
		if err := saveToFile(*mermaidFile, visualizer.GenerateMermaid()); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving Mermaid file: %v\n", err)
		} else if *verbose {
			fmt.Printf("Mermaid diagram saved to: %s\n", *mermaidFile)
		}
	}
	
	if *verbose {
		fmt.Printf("\nAnalysis complete. Processed %d packets in %s\n", 
			result.PacketsAnalyzed, result.ProcessingTime)
	}
}

func showUsage() {
	fmt.Fprintf(os.Stderr, `Janus Phase 4 - N-Point Packet Correlation Tool

Usage:
  %s [options] -pcap file1.pcap -pcap file2.pcap [-pcap file3.pcap ...]

Required Arguments:
  -pcap string         PCAP file (can be specified multiple times)
  -point string        Capture point name (optional, defaults to filename)

Output Options:
  -format string       Output format: table, json, graphviz, mermaid (default "table")
  -graphviz string     Save Graphviz DOT file
  -mermaid string      Save Mermaid diagram file
  -top-paths int       Number of top flow paths to show (default 10)
  -flow-details string Show detailed path for specific flow key

Analysis Configuration:
  -max-time-delta duration     Maximum time delta for correlation (default 5s)
  -min-confidence float        Minimum confidence threshold (default 0.7)
  -bidirectional              Track bidirectional flows (default true)
  -partial-paths              Include partial flow paths (default false)

Correlation Methods:
  -enable-ipid        Enable IP ID correlation (default true)
  -enable-payload     Enable payload hash correlation (default true)
  -enable-tcp-seq     Enable TCP sequence correlation (default true)
  -enable-timing      Enable timing pattern correlation (default true)

Performance Tuning:
  -workers int        Number of worker goroutines (default 4)
  -batch-size int     Batch size for processing (default 1000)
  -max-memory int     Maximum memory usage in MB (default 1024)

General Options:
  -verbose           Enable verbose output
  -help              Show this help message

Examples:
  # Basic 3-point correlation
  %s -pcap router1.pcap -pcap router2.pcap -pcap router3.pcap

  # With custom point names
  %s -pcap r1.pcap -point "Router-1" -pcap r2.pcap -point "Router-2"

  # Generate Graphviz visualization
  %s -pcap *.pcap -format graphviz > flows.dot

  # Performance tuning for large files
  %s -pcap *.pcap -workers 8 -batch-size 2000 -max-memory 2048

  # Focus on specific correlation methods
  %s -pcap *.pcap -enable-ipid=false -enable-timing=false

  # Show detailed path for specific flow
  %s -pcap *.pcap -flow-details "tcp:192.168.1.1:80->10.0.0.1:443"

Build with: go build -tags phase4 -o janus-phase4 ./cmd/janus
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}

func saveToFile(filename, content string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	_, err = file.WriteString(content)
	return err
}