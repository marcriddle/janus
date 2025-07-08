package live

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestLiveCaptureInterface(t *testing.T) {
	tests := []struct {
		name        string
		config      LiveCaptureConfig
		expectError bool
	}{
		{
			name: "valid single interface",
			config: LiveCaptureConfig{
				Interfaces:  []string{"lo"},
				SnapLength:  65536,
				Promiscuous: false,
				Timeout:     time.Second,
				BufferSize:  1024 * 1024,
			},
			expectError: false,
		},
		{
			name: "invalid interface",
			config: LiveCaptureConfig{
				Interfaces: []string{"nonexistent999"},
				SnapLength: 65536,
			},
			expectError: true,
		},
		{
			name: "multiple interfaces",
			config: LiveCaptureConfig{
				Interfaces: []string{"lo", "any"},
				SnapLength: 1500,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capture, err := NewLiveCapture(tt.config)
			
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			
			if capture == nil {
				t.Fatal("Expected non-nil capture")
			}
			
			// Verify configuration
			if len(capture.GetInterfaces()) != len(tt.config.Interfaces) {
				t.Errorf("Expected %d interfaces, got %d", len(tt.config.Interfaces), len(capture.GetInterfaces()))
			}
			
			// Cleanup
			capture.Close()
		})
	}
}

func TestLiveCaptureStartStop(t *testing.T) {
	config := LiveCaptureConfig{
		Interfaces: []string{"lo"},
		SnapLength: 65536,
		Timeout:    time.Millisecond * 100,
	}
	
	capture, err := NewLiveCapture(config)
	if err != nil {
		t.Fatalf("Failed to create capture: %v", err)
	}
	defer capture.Close()
	
	// Test starting capture
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	
	err = capture.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start capture: %v", err)
	}
	
	// Verify capture is running
	if !capture.IsRunning() {
		t.Error("Expected capture to be running")
	}
	
	// Generate some local traffic to capture
	go generateLocalTraffic(t)
	
	// Collect packets for a short time
	packetCount := 0
	timeout := time.After(time.Second * 2)
	
	for {
		select {
		case packet := <-capture.Packets():
			if packet != nil {
				packetCount++
				if packetCount >= 1 {
					goto stopTest // Got at least one packet
				}
			}
		case err := <-capture.Errors():
			t.Logf("Capture error (may be expected): %v", err)
		case <-timeout:
			goto stopTest
		}
	}
	
stopTest:
	// Test stopping capture
	err = capture.Stop()
	if err != nil {
		t.Errorf("Failed to stop capture: %v", err)
	}
	
	// Verify capture is stopped
	if capture.IsRunning() {
		t.Error("Expected capture to be stopped")
	}
	
	t.Logf("Captured %d packets during test", packetCount)
}

func TestLiveCaptureFiltering(t *testing.T) {
	config := LiveCaptureConfig{
		Interfaces: []string{"lo"},
		SnapLength: 65536,
		Filters: map[string]string{
			"lo": "icmp or tcp port 12345",
		},
	}
	
	capture, err := NewLiveCapture(config)
	if err != nil {
		t.Fatalf("Failed to create capture: %v", err)
	}
	defer capture.Close()
	
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	
	err = capture.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start capture: %v", err)
	}
	defer capture.Stop()
	
	// Generate filtered traffic
	go func() {
		// This should be captured (TCP port 12345)
		conn, err := net.Dial("tcp", "127.0.0.1:12345")
		if err == nil {
			conn.Close()
		}
	}()
	
	// Wait for packets
	timeout := time.After(time.Second * 2)
	packetReceived := false
	
	for {
		select {
		case packet := <-capture.Packets():
			if packet != nil {
				packetReceived = true
				// Verify the packet matches our filter
				if packet.NetworkLayer() != nil {
					t.Logf("Received filtered packet: %v", packet.NetworkLayer())
				}
				goto endFiltering
			}
		case <-timeout:
			goto endFiltering
		}
	}
	
endFiltering:
	if !packetReceived {
		t.Log("No packets received (this may be expected if no traffic matches filter)")
	}
}

func TestLiveCaptureBufferOverflow(t *testing.T) {
	// Test with very small buffer to trigger overflow
	config := LiveCaptureConfig{
		Interfaces: []string{"lo"},
		SnapLength: 65536,
		BufferSize: 1024, // Very small buffer
		Timeout:    time.Millisecond * 10,
	}
	
	capture, err := NewLiveCapture(config)
	if err != nil {
		t.Fatalf("Failed to create capture: %v", err)
	}
	defer capture.Close()
	
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	
	err = capture.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start capture: %v", err)
	}
	defer capture.Stop()
	
	// Generate lots of traffic to overflow buffer
	go func() {
		for i := 0; i < 100; i++ {
			generateLocalTraffic(t)
			time.Sleep(time.Millisecond)
		}
	}()
	
	// Monitor for drops or errors
	timeout := time.After(time.Second * 2)
	dropsDetected := false
	
	for {
		select {
		case stats := <-capture.Stats():
			if stats.PacketsDropped > 0 {
				dropsDetected = true
				t.Logf("Buffer overflow detected: %d packets dropped", stats.PacketsDropped)
				goto endOverflow
			}
		case <-capture.Errors():
			// Errors are expected with small buffer
		case <-capture.Packets():
			// Consume packets
		case <-timeout:
			goto endOverflow
		}
	}
	
endOverflow:
	t.Logf("Buffer overflow test completed, drops detected: %v", dropsDetected)
}

func TestLiveCaptureMultipleInterfaces(t *testing.T) {
	// Skip if we don't have multiple interfaces
	interfaces, err := getAvailableInterfaces()
	if err != nil || len(interfaces) < 2 {
		t.Skip("Skipping multiple interface test - not enough interfaces available")
	}
	
	config := LiveCaptureConfig{
		Interfaces: interfaces[:2], // Use first two interfaces
		SnapLength: 65536,
	}
	
	capture, err := NewLiveCapture(config)
	if err != nil {
		t.Fatalf("Failed to create capture: %v", err)
	}
	defer capture.Close()
	
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	
	err = capture.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start capture: %v", err)
	}
	defer capture.Stop()
	
	// Track packets per interface
	interfacePackets := make(map[string]int)
	timeout := time.After(time.Second * 2)
	
	for {
		select {
		case packet := <-capture.Packets():
			if packet != nil && packet.Metadata() != nil {
				interfaceName := packet.Metadata().InterfaceIndex
				interfacePackets[string(rune(interfaceName))]++
			}
		case <-timeout:
			goto endMulti
		}
	}
	
endMulti:
	t.Logf("Packets per interface: %v", interfacePackets)
}

func TestLiveCaptureMetrics(t *testing.T) {
	config := LiveCaptureConfig{
		Interfaces: []string{"lo"},
		SnapLength: 65536,
	}
	
	capture, err := NewLiveCapture(config)
	if err != nil {
		t.Fatalf("Failed to create capture: %v", err)
	}
	defer capture.Close()
	
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	
	err = capture.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start capture: %v", err)
	}
	defer capture.Stop()
	
	// Generate some traffic
	go generateLocalTraffic(t)
	
	// Wait a bit for packets
	time.Sleep(time.Millisecond * 500)
	
	// Check metrics
	select {
	case stats := <-capture.Stats():
		if stats.PacketsReceived < 0 {
			t.Error("Invalid packets received count")
		}
		if stats.BytesReceived < 0 {
			t.Error("Invalid bytes received count")
		}
		t.Logf("Capture stats: %+v", stats)
	case <-time.After(time.Second):
		t.Log("No stats received (may be expected)")
	}
}

func TestLiveCaptureGracefulShutdown(t *testing.T) {
	config := LiveCaptureConfig{
		Interfaces: []string{"lo"},
		SnapLength: 65536,
	}
	
	capture, err := NewLiveCapture(config)
	if err != nil {
		t.Fatalf("Failed to create capture: %v", err)
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	
	err = capture.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start capture: %v", err)
	}
	
	// Start consuming packets
	var wg sync.WaitGroup
	wg.Add(1)
	
	go func() {
		defer wg.Done()
		for {
			select {
			case packet := <-capture.Packets():
				if packet == nil {
					return // Channel closed
				}
			case <-capture.Errors():
				// Continue on errors
			case <-ctx.Done():
				return
			}
		}
	}()
	
	// Let it run briefly
	time.Sleep(time.Millisecond * 100)
	
	// Test graceful shutdown
	err = capture.Stop()
	if err != nil {
		t.Errorf("Failed to stop capture gracefully: %v", err)
	}
	
	// Ensure channels are closed
	wg.Wait()
	
	// Verify cleanup
	if capture.IsRunning() {
		t.Error("Capture should be stopped")
	}
	
	// Test double close
	err = capture.Close()
	if err != nil {
		t.Errorf("First close failed: %v", err)
	}
	
	err = capture.Close()
	if err != nil {
		t.Errorf("Second close should not error: %v", err)
	}
}

// Helper functions

func generateLocalTraffic(t *testing.T) {
	// Generate some local network traffic for testing
	// This is safe as it only connects to localhost
	
	// Try TCP connection
	conn, err := net.DialTimeout("tcp", "127.0.0.1:80", time.Millisecond*100)
	if err == nil {
		conn.Close()
	}
	
	// Try UDP "connection"
	conn, err = net.DialTimeout("udp", "127.0.0.1:53", time.Millisecond*100)
	if err == nil {
		conn.Write([]byte("test"))
		conn.Close()
	}
}

func getAvailableInterfaces() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	
	var names []string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 {
			names = append(names, iface.Name)
		}
	}
	
	return names, nil
}

// Mock packet for testing
func createMockPacket() gopacket.Packet {
	// Create a simple TCP packet for testing
	ipLayer := &layers.IPv4{
		SrcIP:    net.IP{127, 0, 0, 1},
		DstIP:    net.IP{127, 0, 0, 1},
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		IHL:      5,
		TTL:      64,
	}
	
	tcpLayer := &layers.TCP{
		SrcPort: 12345,
		DstPort: 80,
		Seq:     1000,
		Ack:     2000,
		SYN:     true,
		Window:  65535,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	
	payload := []byte("test payload")
	gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer, gopacket.Payload(payload))
	
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}