package correlator

import (
	"net"
	"testing"
	"time"

	"github.com/janus-project/janus/pkg/types"
)

func TestCorrelator_ProcessPacket(t *testing.T) {
	corr := New()

	// Create test packet observations
	capture1 := &types.CapturePointInfo{
		PointID: "point1",
		Packet: types.PacketInfo{
			Timestamp: time.Now(),
			IPID:      12345,
			TTL:       64,
			SrcIP:     net.ParseIP("192.168.1.10"),
			DstIP:     net.ParseIP("10.0.0.1"),
			SrcPort:   54321,
			DstPort:   80,
			Protocol:  "tcp",
			TCPSeq:    1000,
		},
	}

	capture2 := &types.CapturePointInfo{
		PointID: "point2",
		Packet: types.PacketInfo{
			Timestamp: time.Now().Add(5 * time.Millisecond),
			IPID:      12345,
			TTL:       63, // TTL decremented
			SrcIP:     net.ParseIP("192.168.1.10"),
			DstIP:     net.ParseIP("10.0.0.1"),
			SrcPort:   54321,
			DstPort:   80,
			Protocol:  "tcp",
			TCPSeq:    1000,
		},
	}

	// Process packets
	corr.ProcessPacket(capture1)
	corr.ProcessPacket(capture2)

	// Check that flow was created
	flows := corr.GetFlowSummary()
	if len(flows) != 1 {
		t.Errorf("Expected 1 flow, got %d", len(flows))
	}

	// Check IP ID map
	ipidKey := "192.168.1.10:12345"
	if observations, exists := corr.ipidMap[ipidKey]; !exists {
		t.Error("IP ID not found in map")
	} else if len(observations) != 2 {
		t.Errorf("Expected 2 observations for IP ID, got %d", len(observations))
	}
}

func TestCorrelator_CorrelatePackets(t *testing.T) {
	corr := New()

	baseTime := time.Now()

	// Create matching packets
	capture1 := &types.CapturePointInfo{
		PointID: "point1",
		Packet: types.PacketInfo{
			Timestamp: baseTime,
			IPID:      12345,
			TTL:       64,
			SrcIP:     net.ParseIP("192.168.1.10"),
			DstIP:     net.ParseIP("10.0.0.1"),
			SrcPort:   54321,
			DstPort:   80,
			Protocol:  "tcp",
			TCPSeq:    1000,
		},
	}

	capture2 := &types.CapturePointInfo{
		PointID: "point2",
		Packet: types.PacketInfo{
			Timestamp: baseTime.Add(5 * time.Millisecond),
			IPID:      12345,
			TTL:       63,
			SrcIP:     net.ParseIP("192.168.1.10"),
			DstIP:     net.ParseIP("10.0.0.1"),
			SrcPort:   54321,
			DstPort:   80,
			Protocol:  "tcp",
			TCPSeq:    1000,
		},
	}

	// Process packets
	corr.ProcessPacket(capture1)
	corr.ProcessPacket(capture2)

	// Correlate
	results := corr.CorrelatePackets("point1", "point2")

	if len(results) != 1 {
		t.Fatalf("Expected 1 correlation result, got %d", len(results))
	}

	result := results[0]

	// Check latency
	expectedLatency := 5 * time.Millisecond
	if result.Latency != expectedLatency {
		t.Errorf("Expected latency %v, got %v", expectedLatency, result.Latency)
	}

	// Check modifications detected
	if !result.PacketModified {
		t.Error("Expected packet modifications to be detected")
	}

	// Check TTL decrement detection
	ttlModFound := false
	for _, mod := range result.Modifications {
		if mod == "TTL decremented: 64 -> 63 (1 hop)" {
			ttlModFound = true
			break
		}
	}
	if !ttlModFound {
		t.Error("Expected TTL decrement to be detected")
	}
}

func TestCorrelator_NATDetection(t *testing.T) {
	corr := New()

	baseTime := time.Now()

	// Create packets with NAT
	capture1 := &types.CapturePointInfo{
		PointID: "point1",
		Packet: types.PacketInfo{
			Timestamp: baseTime,
			IPID:      12345,
			TTL:       64,
			SrcIP:     net.ParseIP("192.168.1.10"),
			DstIP:     net.ParseIP("10.0.0.1"),
			SrcPort:   54321,
			DstPort:   80,
			Protocol:  "tcp",
			TCPSeq:    1000,
		},
	}

	// Packet after NAT
	capture2 := &types.CapturePointInfo{
		PointID: "point2",
		Packet: types.PacketInfo{
			Timestamp: baseTime.Add(5 * time.Millisecond),
			IPID:      12345,
			TTL:       63,
			SrcIP:     net.ParseIP("203.0.113.7"), // NAT'd source IP
			DstIP:     net.ParseIP("10.0.0.1"),
			SrcPort:   18311, // NAT'd source port
			DstPort:   80,
			Protocol:  "tcp",
			TCPSeq:    1000,
		},
	}

	// Process packets
	corr.ProcessPacket(capture1)
	corr.ProcessPacket(capture2)

	// Since NAT changes the flow key, these won't correlate in Phase 1
	// This is a limitation of IP ID-only matching
	results := corr.CorrelatePackets("point1", "point2")

	// In Phase 1, NAT'd packets won't correlate because we're only using IP ID
	// and checking that source IPs match
	if len(results) != 0 {
		t.Errorf("Expected 0 correlations for NAT'd packets in Phase 1, got %d", len(results))
	}
}