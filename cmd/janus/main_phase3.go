// +build phase3

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/janus-project/janus/pkg/correlator"
	"github.com/janus-project/janus/pkg/nat"
	januspcap "github.com/janus-project/janus/pkg/pcap"
	"github.com/janus-project/janus/pkg/stream"
	"github.com/janus-project/janus/pkg/types"
)

func main() {
	var (
		// Basic flags
		verbose bool
		output  string
		
		// Mode flags
		natMode    bool
		streamMode bool
		
		// NAT specific flags
		natReport   bool
		natGraphviz string
		detectCGNAT bool
		
		// Multi-file support
		pcapFiles   stringSlice
		pointNames  stringSlice
	)

	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")
	flag.StringVar(&output, "output", "", "Output file for results (default: stdout)")
	
	// Mode flags
	flag.BoolVar(&natMode, "nat", false, "Enable NAT detection and analysis")
	flag.BoolVar(&streamMode, "stream", false, "Enable stream reassembly mode")
	
	// NAT specific
	flag.BoolVar(&natReport, "nat-report", false, "Generate detailed NAT analysis report")
	flag.StringVar(&natGraphviz, "nat-graphviz", "", "Generate Graphviz output for NAT flows")
	flag.BoolVar(&detectCGNAT, "detect-cgnat", true, "Enable CGNAT detection")
	
	// Multi-file support
	flag.Var(&pcapFiles, "pcap", "PCAP file to analyze (can be specified multiple times)")
	flag.Var(&pointNames, "point", "Capture point name (matches order of -pcap flags)")
	
	// Legacy compatibility
	var file1, file2, point1, point2 string
	flag.StringVar(&file1, "pcap1", "", "First PCAP file (legacy)")
	flag.StringVar(&file2, "pcap2", "", "Second PCAP file (legacy)")
	flag.StringVar(&point1, "point1", "", "Name for first capture point (legacy)")
	flag.StringVar(&point2, "point2", "", "Name for second capture point (legacy)")
	
	flag.Parse()

	// Handle legacy arguments
	if file1 != "" && file2 != "" {
		pcapFiles = append(pcapFiles, file1, file2)
		if point1 != "" {
			pointNames = append(pointNames, point1)
		}
		if point2 != "" {
			pointNames = append(pointNames, point2)
		}
	}

	// Validate arguments
	if len(pcapFiles) < 2 {
		fmt.Fprintf(os.Stderr, "Janus Network Path Analysis Tool (Phase 3)\n")
		fmt.Fprintf(os.Stderr, "==========================================\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s -pcap <file1> -pcap <file2> [options]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "   or: %s -pcap1 <file1> -pcap2 <file2> [options] (legacy)\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  Basic correlation:\n")
		fmt.Fprintf(os.Stderr, "    %s -pcap lan.pcap -pcap wan.pcap\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  NAT analysis with report:\n")
		fmt.Fprintf(os.Stderr, "    %s -pcap internal.pcap -pcap external.pcap -nat -nat-report\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Multi-point analysis:\n")
		fmt.Fprintf(os.Stderr, "    %s -pcap lan.pcap -pcap dmz.pcap -pcap wan.pcap -point LAN -point DMZ -point WAN\n", os.Args[0])
		os.Exit(1)
	}

	// Set default point names if not provided
	for i := len(pointNames); i < len(pcapFiles); i++ {
		pointNames = append(pointNames, filepath.Base(pcapFiles[i]))
	}

	// Open output file if specified
	var outFile *os.File
	if output != "" {
		var err error
		outFile, err = os.Create(output)
		if err != nil {
			log.Fatalf("Failed to create output file: %v", err)
		}
		defer outFile.Close()
	} else {
		outFile = os.Stdout
	}

	// Read all PCAP files
	allPackets := make([][]*types.CapturePointInfo, 0, len(pcapFiles))
	for i, pcapFile := range pcapFiles {
		if verbose {
			log.Printf("Reading PCAP file: %s (point: %s)", pcapFile, pointNames[i])
		}
		
		packets, err := januspcap.ReadAllPackets(pcapFile, pointNames[i])
		if err != nil {
			log.Fatalf("Failed to read %s: %v", pcapFile, err)
		}
		
		if verbose {
			log.Printf("Read %d packets from %s", len(packets), pcapFile)
		}
		
		allPackets = append(allPackets, packets)
	}

	// Perform NAT analysis if requested
	if natMode {
		performNATAnalysis(allPackets, pointNames, natReport, natGraphviz, detectCGNAT, verbose, outFile)
		return
	}

	// Perform standard correlation (enhanced with stream support)
	performCorrelation(allPackets, pointNames, streamMode, verbose, outFile)
}

func performNATAnalysis(allPackets [][]*types.CapturePointInfo, pointNames []string, 
	generateReport bool, graphvizFile string, detectCGNAT bool, verbose bool, outFile *os.File) {
	
	fmt.Fprintf(outFile, "\nJanus NAT Analysis (Phase 3)\n")
	fmt.Fprintf(outFile, "============================\n\n")

	// Create NAT detector with configuration
	cfg := nat.DefaultConfig()
	cfg.DetectCGNAT = detectCGNAT
	detector := nat.NewDetector(cfg)
	
	// Create transformer and tracker
	transformer := nat.NewTransformer()
	tracker := nat.NewConnectionTracker()

	// Process packets between each pair of capture points
	for i := 0; i < len(allPackets)-1; i++ {
		for j := i + 1; j < len(allPackets); j++ {
			if verbose {
				log.Printf("Analyzing NAT between %s and %s", pointNames[i], pointNames[j])
			}
			
			// Simple correlation based on timing and flow
			correlateAndDetectNAT(detector, transformer, tracker, 
				allPackets[i], allPackets[j], pointNames[i], pointNames[j], verbose)
		}
	}

	// Analyze results
	result := detector.AnalyzeFlows()
	
	// Print summary
	fmt.Fprintf(outFile, "NAT Detection Summary:\n")
	fmt.Fprintf(outFile, "---------------------\n")
	fmt.Fprintf(outFile, "Total flows analyzed: %d\n", result.TotalFlows)
	fmt.Fprintf(outFile, "NAT-modified flows: %d (%.1f%%)\n", 
		result.NATtedFlows, float64(result.NATtedFlows)/float64(result.TotalFlows)*100)
	fmt.Fprintf(outFile, "Detection confidence: %.1f%%\n", result.Confidence*100)
	
	if result.DoubleNATFlows > 0 {
		fmt.Fprintf(outFile, "⚠️  Double NAT detected: %d flows\n", result.DoubleNATFlows)
	}
	
	// Print findings
	if len(result.Findings) > 0 {
		fmt.Fprintf(outFile, "\nKey Findings:\n")
		for _, finding := range result.Findings {
			fmt.Fprintf(outFile, "  • %s\n", finding)
		}
	}

	// Generate detailed report if requested
	if generateReport {
		fmt.Fprintf(outFile, "\n")
		reporter := nat.NewReporter(detector, transformer, tracker)
		if err := reporter.GenerateReport(outFile); err != nil {
			log.Printf("Error generating report: %v", err)
		}
	}

	// Generate Graphviz output if requested
	if graphvizFile != "" {
		graphFile, err := os.Create(graphvizFile)
		if err != nil {
			log.Printf("Failed to create Graphviz file: %v", err)
		} else {
			defer graphFile.Close()
			reporter := nat.NewReporter(detector, transformer, tracker)
			if err := reporter.GenerateGraphviz(graphFile); err != nil {
				log.Printf("Error generating Graphviz: %v", err)
			} else {
				fmt.Fprintf(outFile, "\nGraphviz output written to: %s\n", graphvizFile)
				fmt.Fprintf(outFile, "Generate PNG with: dot -Tpng %s -o nat-diagram.png\n", graphvizFile)
			}
		}
	}
}

func performCorrelation(allPackets [][]*types.CapturePointInfo, pointNames []string, 
	streamMode bool, verbose bool, outFile *os.File) {
	
	// Create correlator
	corr := correlator.New()
	
	// Handle stream mode
	if streamMode && len(allPackets) >= 2 {
		// Use the enhanced stream analysis from Phase 2
		runStreamAnalysis(pcapFiles[0], pcapFiles[1], pointNames[0], pointNames[1], corr, verbose)
		return
	}
	
	fmt.Fprintf(outFile, "\nJanus Network Path Correlation Analysis\n")
	fmt.Fprintf(outFile, "=====================================\n\n")

	// Process all packets
	for i, packets := range allPackets {
		if verbose {
			log.Printf("Processing %d packets from %s", len(packets), pointNames[i])
		}
		for _, pkt := range packets {
			corr.ProcessPacket(pkt)
		}
	}

	// Perform correlation between first two points (for compatibility)
	if len(allPackets) >= 2 {
		results := corr.CorrelatePackets(pointNames[0], pointNames[1])
		
		fmt.Fprintf(outFile, "Point 1: %s (%s)\n", pointNames[0], pcapFiles[0])
		fmt.Fprintf(outFile, "Point 2: %s (%s)\n", pointNames[1], pcapFiles[1])
		fmt.Fprintf(outFile, "\nCorrelation Results:\n")
		fmt.Fprintf(outFile, "-------------------\n")
		
		if len(results) == 0 {
			fmt.Fprintln(outFile, "No packet correlations found between the two capture points.")
			fmt.Fprintln(outFile, "\nPossible reasons:")
			fmt.Fprintln(outFile, "- The captures don't contain the same traffic")
			fmt.Fprintln(outFile, "- Time synchronization issues between capture hosts")
			fmt.Fprintln(outFile, "- Packets were heavily modified (NAT, etc.)")
			if !streamMode {
				fmt.Fprintln(outFile, "- Try -stream mode for TCP stream reassembly")
			}
		} else {
			printCorrelationResults(results, outFile)
			fmt.Fprintf(outFile, "\nTotal correlations: %d\n", len(results))
		}
	}

	// Show flow summary if verbose
	if verbose {
		fmt.Fprintf(outFile, "\n\nFlow Summary:\n")
		fmt.Fprintf(outFile, "-------------\n")
		flows := corr.GetFlowSummary()
		for flow, path := range flows {
			fmt.Fprintf(outFile, "Flow %s:\n", flow)
			for _, point := range path {
				fmt.Fprintf(outFile, "  - %s at %s\n", point.PointID, point.Packet.Timestamp.Format("15:04:05.000000"))
			}
		}
	}
}

func correlateAndDetectNAT(detector *nat.Detector, transformer *nat.Transformer, 
	tracker *nat.ConnectionTracker, packets1, packets2 []*types.CapturePointInfo, 
	point1, point2 string, verbose bool) {
	
	// Simple time-based correlation
	// In a real implementation, this would use the enhanced correlator
	for _, p1 := range packets1 {
		for _, p2 := range packets2 {
			// Check if packets might be related (same protocol, similar timing)
			if p1.Packet.Protocol == p2.Packet.Protocol {
				timeDiff := p2.Packet.Timestamp.Sub(p1.Packet.Timestamp).Abs()
				if timeDiff < 100*time.Millisecond {
					// Potential correlation - check for NAT
					if entry, err := detector.DetectNAT(p1, p2); err == nil && entry != nil {
						tracker.TrackPacket(p1, entry)
						if verbose {
							log.Printf("NAT detected: %s", entry)
						}
					}
				}
			}
		}
	}
}

func printCorrelationResults(results []correlator.CorrelationResult, outFile *os.File) {
	for i, result := range results {
		fmt.Fprintf(outFile, "\n[%d] Flow: %s\n", i+1, result.Flow)
		
		// Basic match info
		fmt.Fprintf(outFile, "    Packet observed at both points (IP ID: %d)\n", result.Point1.Packet.IPID)
		fmt.Fprintf(outFile, "    %s: %s\n", result.Point1.PointID, result.Point1.Packet.Timestamp.Format("15:04:05.000000"))
		fmt.Fprintf(outFile, "    %s: %s\n", result.Point2.PointID, result.Point2.Packet.Timestamp.Format("15:04:05.000000"))
		fmt.Fprintf(outFile, "    Latency: %v\n", result.Latency)
		
		if result.PacketModified {
			fmt.Fprintf(outFile, "    Modifications detected:\n")
			for _, mod := range result.Modifications {
				fmt.Fprintf(outFile, "      - %s\n", mod)
			}
		} else {
			fmt.Fprintf(outFile, "    No modifications detected\n")
		}
	}
}

// stringSlice implements flag.Value for repeated string flags
type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// Declare pcapFiles variable at package level
var pcapFiles stringSlice

func runStreamAnalysis(file1, file2, point1, point2 string, corr *correlator.Correlator, verbose bool) {
	// Create stream reassemblers
	reassembler1 := stream.NewStreamReassembler(point1)
	reassembler2 := stream.NewStreamReassembler(point2)

	// Process first PCAP with stream reassembly
	if verbose {
		log.Printf("Processing %s with TCP stream reassembly", file1)
	}
	
	handle1, err := pcap.OpenOffline(file1)
	if err != nil {
		log.Fatalf("Failed to open %s: %v", file1, err)
	}
	defer handle1.Close()

	packetSource1 := gopacket.NewPacketSource(handle1, handle1.LinkType())
	count1 := 0
	for packet := range packetSource1.Packets() {
		count1++
		reassembler1.ProcessPacket(packet)
		
		// Also process for packet-level correlation
		if info := extractPacketInfo(packet, point1); info != nil {
			corr.ProcessPacket(info)
		}
	}
	reassembler1.FlushAll()

	// Process second PCAP with stream reassembly
	if verbose {
		log.Printf("Processing %s with TCP stream reassembly", file2)
	}
	
	handle2, err := pcap.OpenOffline(file2)
	if err != nil {
		log.Fatalf("Failed to open %s: %v", file2, err)
	}
	defer handle2.Close()

	packetSource2 := gopacket.NewPacketSource(handle2, handle2.LinkType())
	count2 := 0
	for packet := range packetSource2.Packets() {
		count2++
		reassembler2.ProcessPacket(packet)
		
		// Also process for packet-level correlation
		if info := extractPacketInfo(packet, point2); info != nil {
			corr.ProcessPacket(info)
		}
	}
	reassembler2.FlushAll()

	// Set stream data in correlator
	corr.SetStreamData(point1, reassembler1.GetStreams())
	corr.SetStreamData(point2, reassembler2.GetStreams())

	// Print results
	fmt.Printf("\nJanus Network Path Correlation Analysis (Phase 2)\n")
	fmt.Printf("===============================================\n")
	fmt.Printf("Point 1: %s (%s) - %d packets\n", point1, file1, count1)
	fmt.Printf("Point 2: %s (%s) - %d packets\n", point2, file2, count2)

	// Stream-based correlations
	streamResults := corr.CorrelateStreams(point1, point2)
	fmt.Printf("\n[TCP Stream Correlations]\n")
	fmt.Printf("------------------------\n")
	
	if len(streamResults) == 0 {
		fmt.Println("No TCP stream correlations found.")
	} else {
		for i, result := range streamResults {
			fmt.Printf("\n[%d] Stream Match (Hash: %s...)\n", i+1, result.PayloadHash[:16])
			fmt.Printf("    Flow @ %s: %s\n", point1, result.Flow1)
			fmt.Printf("    Flow @ %s: %s\n", point2, result.Flow2)
			fmt.Printf("    Payload: %d bytes in %d packets\n", result.Stream1.PayloadSize, result.Stream1.Packets)
			fmt.Printf("    Latency: %v\n", result.Latency)
			
			if result.StreamModified {
				fmt.Printf("    Modifications:\n")
				for _, mod := range result.Modifications {
					fmt.Printf("      - %s\n", mod)
				}
			}
		}
		fmt.Printf("\nTotal stream correlations: %d\n", len(streamResults))
	}

	// Packet-level correlations with enhanced matching
	packetResults := corr.CorrelatePackets(point1, point2)
	fmt.Printf("\n[Enhanced Packet Correlations]\n")
	fmt.Printf("------------------------------\n")
	
	if len(packetResults) == 0 {
		fmt.Println("No packet correlations found.")
	} else {
		displayed := 0
		for _, result := range packetResults {
			if displayed < 5 || verbose {
				displayed++
				fmt.Printf("\n[%d] %s\n", displayed, result.Flow)
				fmt.Printf("    Strategy: %s (Confidence: %.2f)\n", result.MatchStrategy, result.MatchConfidence)
				fmt.Printf("    Latency: %v\n", result.Latency)
				if result.PacketModified {
					for _, mod := range result.Modifications {
						fmt.Printf("    - %s\n", mod)
					}
				}
			}
		}
		
		if displayed < len(packetResults) && !verbose {
			fmt.Printf("\n... and %d more (use -verbose to see all)\n", len(packetResults)-displayed)
		}
		fmt.Printf("\nTotal packet correlations: %d\n", len(packetResults))
	}
}

func extractPacketInfo(packet gopacket.Packet, pointID string) *types.CapturePointInfo {
	info := &types.PacketInfo{
		Timestamp: packet.Metadata().Timestamp,
	}

	// Extract IPv4 layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		info.SrcIP = ip.SrcIP
		info.DstIP = ip.DstIP
		info.IPID = ip.Id
		info.TTL = ip.TTL
		info.Protocol = ip.Protocol.String()
	} else {
		return nil // Skip non-IPv4 for now
	}

	// Extract transport layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		info.SrcPort = uint16(tcp.SrcPort)
		info.DstPort = uint16(tcp.DstPort)
		info.TCPSeq = tcp.Seq
		info.TCPAck = tcp.Ack
		info.Protocol = "tcp"
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		info.SrcPort = uint16(udp.SrcPort)
		info.DstPort = uint16(udp.DstPort)
		info.Protocol = "udp"
	}

	return &types.CapturePointInfo{
		PointID: pointID,
		Packet:  *info,
	}
}