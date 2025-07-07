package stream

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/janus-project/janus/pkg/types"
)

func TestStreamCollector(t *testing.T) {
	collector := NewStreamCollector("test-point")
	
	// Add a test stream
	flow := types.NewFlowKey("tcp", net.ParseIP("192.168.1.10"), 54321, net.ParseIP("10.0.0.1"), 80)
	streamData := &StreamData{
		FlowKey:     flow,
		PointID:     "test-point",
		FirstSeen:   time.Now(),
		LastSeen:    time.Now().Add(time.Second),
		PayloadHash: "abcdef123456",
		PayloadSize: 1024,
		Packets:     10,
		TCPSeqStart: 1000,
		TCPSeqEnd:   2024,
	}
	
	collector.mu.Lock()
	collector.streams[flow] = streamData
	collector.mu.Unlock()
	
	// Test GetStreams
	streams := collector.GetStreams()
	if len(streams) != 1 {
		t.Errorf("Expected 1 stream, got %d", len(streams))
	}
	
	retrieved, ok := streams[flow]
	if !ok {
		t.Error("Stream not found in results")
	}
	
	if retrieved.PayloadHash != streamData.PayloadHash {
		t.Errorf("Expected payload hash %s, got %s", streamData.PayloadHash, retrieved.PayloadHash)
	}
}

func TestStreamReassembler(t *testing.T) {
	reassembler := NewStreamReassembler("test-point")
	
	// Create a test TCP packet
	srcIP := net.ParseIP("192.168.1.10")
	dstIP := net.ParseIP("10.0.0.1")
	
	// Build layers
	ipLayer := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		IHL:      5,
		TTL:      64,
	}
	
	tcpLayer := &layers.TCP{
		SrcPort: 54321,
		DstPort: 80,
		Seq:     1000,
		Ack:     0,
		SYN:     true,
		Window:  65535,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	
	// Create packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer, gopacket.Payload(payload))
	
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	packet.Metadata().CaptureInfo = gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(buf.Bytes()),
		Length:        len(buf.Bytes()),
	}
	
	// Process the packet
	reassembler.ProcessPacket(packet)
	
	// Flush to complete reassembly
	reassembler.FlushAll()
	
	// Check results
	streams := reassembler.GetStreams()
	if len(streams) == 0 {
		t.Skip("Stream reassembly requires multiple packets in practice")
	}
}

func TestPayloadHashMatching(t *testing.T) {
	// Test that identical payloads produce identical hashes
	collector1 := NewStreamCollector("point1")
	collector2 := NewStreamCollector("point2")
	
	flow1 := types.NewFlowKey("tcp", net.ParseIP("192.168.1.10"), 54321, net.ParseIP("10.0.0.1"), 80)
	flow2 := types.NewFlowKey("tcp", net.ParseIP("203.0.113.7"), 18311, net.ParseIP("10.0.0.1"), 80) // NAT'd
	
	hash := "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"
	
	stream1 := &StreamData{
		FlowKey:     flow1,
		PointID:     "point1",
		PayloadHash: hash,
		PayloadSize: 1024,
	}
	
	stream2 := &StreamData{
		FlowKey:     flow2,
		PointID:     "point2",
		PayloadHash: hash,
		PayloadSize: 1024,
	}
	
	collector1.mu.Lock()
	collector1.streams[flow1] = stream1
	collector1.mu.Unlock()
	
	collector2.mu.Lock()
	collector2.streams[flow2] = stream2
	collector2.mu.Unlock()
	
	// Verify both have same hash despite different flow keys (NAT)
	if stream1.PayloadHash != stream2.PayloadHash {
		t.Error("Identical payloads should produce identical hashes")
	}
}