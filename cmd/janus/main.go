// +build !phase3

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/janus-project/janus/pkg/correlator"
	"github.com/janus-project/janus/pkg/pcap"
)

func main() {
	var (
		file1   string
		file2   string
		point1  string
		point2  string
		verbose bool
	)

	flag.StringVar(&file1, "pcap1", "", "First PCAP file")
	flag.StringVar(&file2, "pcap2", "", "Second PCAP file")
	flag.StringVar(&point1, "point1", "", "Name for first capture point (default: filename)")
	flag.StringVar(&point2, "point2", "", "Name for second capture point (default: filename)")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")
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

	// Read first PCAP file
	if verbose {
		log.Printf("Reading PCAP file: %s (point: %s)", file1, point1)
	}
	packets1, err := pcap.ReadAllPackets(file1, point1)
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
	packets2, err := pcap.ReadAllPackets(file2, point2)
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