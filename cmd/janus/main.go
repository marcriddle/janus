// +build !phase3

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/janus-project/janus/pkg/correlator"
	januspcap "github.com/janus-project/janus/pkg/pcap"
	"github.com/janus-project/janus/pkg/stream"
	"github.com/janus-project/janus/pkg/types"
)

func main() {
	var (
		file1        string
		file2        string
		point1       string
		point2       string
		verbose      bool
		skipTTLOnly  bool
		streamMode   bool
	)

	flag.StringVar(&file1, "pcap1", "", "First PCAP file")
	flag.StringVar(&file2, "pcap2", "", "Second PCAP file")
	flag.StringVar(&point1, "point1", "", "Name for first capture point (default: filename)")
	flag.StringVar(&point2, "point2", "", "Name for second capture point (default: filename)")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(&skipTTLOnly, "skip-ttl-only", false, "Skip displaying packets that differ only by TTL (by 1 hop)")
	flag.BoolVar(&streamMode, "stream", false, "Enable TCP stream reassembly mode (Phase 2)")
	flag.Parse()

	// Validate arguments
	if file1 == "" || file2 == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -pcap1 <file1> -pcap2 <file2> [options]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  %s -pcap1 capture1.pcap -pcap2 capture2.pcap -point1 container -point2 host\n", os.Args[0])
		os.Exit(1)
	}

	// Set default point names if not provided
	if point1 == "" {
		point1 = filepath.Base(file1)
	}
	if point2 == "" {
		point2 = filepath.Base(file2)
	}

	// Create correlator
	corr := correlator.New()
	
	// Set skip TTL-only option if specified
	if skipTTLOnly {
		corr.SetSkipTTLOnly(true)
	}

	// Use stream mode if requested
	if streamMode {
		runStreamAnalysis(file1, file2, point1, point2, corr, verbose)
		return
	}

	// Read first PCAP file
	if verbose {
		log.Printf("Reading PCAP file: %s (point: %s)", file1, point1)
	}
	packets1, err := januspcap.ReadAllPackets(file1, point1)
	if err != nil {
		log.Fatalf("Failed to read %s: %v", file1, err)
	}
	if verbose {
		log.Printf("Read %d packets from %s", len(packets1), file1)
	}

	// Read second PCAP file
	if verbose {
		log.Printf("Reading PCAP file: %s (point: %s)", file2, point2)
	}
	packets2, err := januspcap.ReadAllPackets(file2, point2)
	if err != nil {
		log.Fatalf("Failed to read %s: %v", file2, err)
	}
	if verbose {
		log.Printf("Read %d packets from %s", len(packets2), file2)
	}

	// Process all packets
	for _, pkt := range packets1 {
		corr.ProcessPacket(pkt)
	}
	for _, pkt := range packets2 {
		corr.ProcessPacket(pkt)
	}

	// Perform correlation
	results := corr.CorrelatePackets(point1, point2)

	// Print results
	fmt.Printf("\nJanus Network Path Correlation Analysis\n")
	fmt.Printf("=====================================\n")
	fmt.Printf("Point 1: %s (%s)\n", point1, file1)
	fmt.Printf("Point 2: %s (%s)\n", point2, file2)
	fmt.Printf("\nCorrelation Results:\n")
	fmt.Printf("-------------------\n")

	if len(results) == 0 {
		fmt.Println("No packet correlations found between the two capture points.")
		fmt.Println("\nPossible reasons:")
		fmt.Println("- The captures don't contain the same traffic")
		fmt.Println("- Time synchronization issues between capture hosts")
		fmt.Println("- Packets were heavily modified (NAT, etc.)")
	} else {
		for i, result := range results {
			fmt.Printf("\n[%d] Flow: %s\n", i+1, result.Flow)
			fmt.Printf("    Packet observed at both points (IP ID: %d)\n", result.Point1.Packet.IPID)
			fmt.Printf("    %s: %s\n", result.Point1.PointID, result.Point1.Packet.Timestamp.Format("15:04:05.000000"))
			fmt.Printf("    %s: %s\n", result.Point2.PointID, result.Point2.Packet.Timestamp.Format("15:04:05.000000"))
			fmt.Printf("    Latency: %v\n", result.Latency)
			
			if result.PacketModified {
				fmt.Printf("    Modifications detected:\n")
				for _, mod := range result.Modifications {
					fmt.Printf("      - %s\n", mod)
				}
			} else {
				fmt.Printf("    No modifications detected\n")
			}
		}
		fmt.Printf("\nTotal correlations: %d\n", len(results))
	}

	// Show flow summary if verbose
	if verbose {
		fmt.Printf("\n\nFlow Summary:\n")
		fmt.Printf("-------------\n")
		flows := corr.GetFlowSummary()
		for flow, path := range flows {
			fmt.Printf("Flow %s:\n", flow)
			for _, point := range path {
				fmt.Printf("  - %s at %s\n", point.PointID, point.Packet.Timestamp.Format("15:04:05.000000"))
			}
		}
	}
}

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