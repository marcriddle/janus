package live

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/janus-project/janus/pkg/types"
)

func TestStreamingCorrelator(t *testing.T) {
	config := StreamingCorrelatorConfig{
		WindowSize:         time.Second * 5,
		MaxFlows:          1000,
		EvictionPolicy:    LRUEviction,
		CorrelationMethods: []string{"ipid", "payload_hash", "tcp_sequence"},
		MinConfidence:     0.7,
	}

	correlator := NewStreamingCorrelator(config)
	if correlator == nil {
		t.Fatal("Failed to create streaming correlator")
	}

	// Test basic configuration
	if correlator.GetWindowSize() != config.WindowSize {
		t.Errorf("Expected window size %v, got %v", config.WindowSize, correlator.GetWindowSize())
	}

	if correlator.GetMaxFlows() != config.MaxFlows {
		t.Errorf("Expected max flows %d, got %d", config.MaxFlows, correlator.GetMaxFlows())
	}
}

func TestStreamingCorrelatorStartStop(t *testing.T) {
	config := StreamingCorrelatorConfig{
		WindowSize: time.Second * 2,
		MaxFlows:   100,
	}

	correlator := NewStreamingCorrelator(config)
	defer correlator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// Test starting
	err := correlator.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start correlator: %v", err)
	}

	if !correlator.IsRunning() {
		t.Error("Expected correlator to be running")
	}

	// Test stopping
	err = correlator.Stop()
	if err != nil {
		t.Errorf("Failed to stop correlator: %v", err)
	}

	if correlator.IsRunning() {
		t.Error("Expected correlator to be stopped")
	}
}

func TestStreamingCorrelatorPacketProcessing(t *testing.T) {
	config := StreamingCorrelatorConfig{
		WindowSize: time.Second * 3,
		MaxFlows:   100,
	}

	correlator := NewStreamingCorrelator(config)
	defer correlator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	err := correlator.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start correlator: %v", err)
	}
	defer correlator.Stop()

	// Create test packets that should correlate
	flowKey := types.NewFlowKey("tcp", net.ParseIP("192.168.1.1"), 80, net.ParseIP("10.0.0.1"), 443)
	
	packet1 := LivePacket{
		Timestamp: time.Now(),
		PointID:   "point1",
		FlowKey:   flowKey,
		Data: types.PacketInfo{
			IPID:      12345,
			TCPSeq:    1000,
			SrcIP:     net.ParseIP("192.168.1.1"),
			SrcPort:   80,
			DstIP:     net.ParseIP("10.0.0.1"),
			DstPort:   443,
			Protocol:  "tcp",
		},
	}

	packet2 := LivePacket{
		Timestamp: time.Now().Add(time.Millisecond * 100),
		PointID:   "point2",
		FlowKey:   flowKey,
		Data: types.PacketInfo{
			IPID:      12345, // Same IP ID for correlation
			TCPSeq:    1000,
			SrcIP:     net.ParseIP("192.168.1.1"),
			SrcPort:   80,
			DstIP:     net.ParseIP("10.0.0.1"),
			DstPort:   443,
			Protocol:  "tcp",
		},
	}

	// Submit packets for correlation
	err = correlator.ProcessPacket(packet1)
	if err != nil {
		t.Errorf("Failed to process packet1: %v", err)
	}

	err = correlator.ProcessPacket(packet2)
	if err != nil {
		t.Errorf("Failed to process packet2: %v", err)
	}

	// Wait for correlation results
	timeout := time.After(time.Second * 2)
	correlationFound := false

	for {
		select {
		case correlation := <-correlator.Correlations():
			if correlation.FlowKey == flowKey {
				correlationFound = true
				if len(correlation.Points) != 2 {
					t.Errorf("Expected 2 correlation points, got %d", len(correlation.Points))
				}
				if correlation.Confidence < 0.5 {
					t.Errorf("Expected reasonable confidence, got %f", correlation.Confidence)
				}
				t.Logf("Found correlation: %+v", correlation)
				goto endProcessing
			}
		case <-timeout:
			goto endProcessing
		}
	}

endProcessing:
	if !correlationFound {
		t.Error("Expected to find correlation between packets")
	}
}

func TestStreamingCorrelatorWindowExpiration(t *testing.T) {
	config := StreamingCorrelatorConfig{
		WindowSize: time.Millisecond * 500, // Short window for testing
		MaxFlows:   100,
	}

	correlator := NewStreamingCorrelator(config)
	defer correlator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	err := correlator.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start correlator: %v", err)
	}
	defer correlator.Stop()

	flowKey := types.NewFlowKey("tcp", net.ParseIP("192.168.1.1"), 80, net.ParseIP("10.0.0.1"), 443)

	// First packet
	packet1 := LivePacket{
		Timestamp: time.Now(),
		PointID:   "point1",
		FlowKey:   flowKey,
		Data: types.PacketInfo{
			IPID: 12345,
		},
	}

	err = correlator.ProcessPacket(packet1)
	if err != nil {
		t.Errorf("Failed to process packet1: %v", err)
	}

	// Wait for window to expire
	time.Sleep(time.Millisecond * 600)

	// Second packet (should not correlate due to expired window)
	packet2 := LivePacket{
		Timestamp: time.Now(),
		PointID:   "point2",
		FlowKey:   flowKey,
		Data: types.PacketInfo{
			IPID: 12345, // Same IP ID but outside window
		},
	}

	err = correlator.ProcessPacket(packet2)
	if err != nil {
		t.Errorf("Failed to process packet2: %v", err)
	}

	// Should not find correlation due to window expiration
	timeout := time.After(time.Second)
	select {
	case correlation := <-correlator.Correlations():
		if correlation.FlowKey == flowKey {
			t.Error("Unexpected correlation found for expired window")
		}
	case <-timeout:
		// Expected - no correlation due to expired window
		t.Log("No correlation found as expected (window expired)")
	}
}

func TestStreamingCorrelatorFlowEviction(t *testing.T) {
	config := StreamingCorrelatorConfig{
		WindowSize:     time.Second * 10,
		MaxFlows:       2, // Very small for testing eviction
		EvictionPolicy: LRUEviction,
	}

	correlator := NewStreamingCorrelator(config)
	defer correlator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	err := correlator.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start correlator: %v", err)
	}
	defer correlator.Stop()

	// Create three different flows
	flow1 := types.NewFlowKey("tcp", net.ParseIP("192.168.1.1"), 80, net.ParseIP("10.0.0.1"), 443)
	flow2 := types.NewFlowKey("tcp", net.ParseIP("192.168.1.2"), 80, net.ParseIP("10.0.0.1"), 443)
	flow3 := types.NewFlowKey("tcp", net.ParseIP("192.168.1.3"), 80, net.ParseIP("10.0.0.1"), 443)

	// Add packets for each flow
	packets := []LivePacket{
		{Timestamp: time.Now(), PointID: "point1", FlowKey: flow1, Data: types.PacketInfo{IPID: 1}},
		{Timestamp: time.Now(), PointID: "point1", FlowKey: flow2, Data: types.PacketInfo{IPID: 2}},
		{Timestamp: time.Now(), PointID: "point1", FlowKey: flow3, Data: types.PacketInfo{IPID: 3}}, // Should evict flow1
	}

	for _, packet := range packets {
		err = correlator.ProcessPacket(packet)
		if err != nil {
			t.Errorf("Failed to process packet: %v", err)
		}
		time.Sleep(time.Millisecond * 10) // Small delay to ensure ordering
	}

	// Verify eviction occurred
	stats := correlator.GetStats()
	if stats.ActiveFlows > 2 {
		t.Errorf("Expected max 2 active flows, got %d", stats.ActiveFlows)
	}

	if stats.EvictedFlows == 0 {
		t.Error("Expected some flows to be evicted")
	}

	t.Logf("Eviction stats: %+v", stats)
}

func TestStreamingCorrelatorConcurrency(t *testing.T) {
	config := StreamingCorrelatorConfig{
		WindowSize: time.Second * 5,
		MaxFlows:   1000,
		WorkerCount: 4,
	}

	correlator := NewStreamingCorrelator(config)
	defer correlator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	err := correlator.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start correlator: %v", err)
	}
	defer correlator.Stop()

	// Test concurrent packet processing
	var wg sync.WaitGroup
	packetCount := 100
	correlationCount := 0
	var mu sync.Mutex

	// Start correlation consumer
	wg.Add(1)
	go func() {
		defer wg.Done()
		timeout := time.After(time.Second * 5)
		for {
			select {
			case correlation := <-correlator.Correlations():
				mu.Lock()
				correlationCount++
				mu.Unlock()
				_ = correlation
			case <-timeout:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	// Generate packets concurrently
	for i := 0; i < packetCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			flowKey := types.NewFlowKey("tcp", 
				net.ParseIP("192.168.1.1"), 
				uint16(80+id%10), 
				net.ParseIP("10.0.0.1"), 
				443)

			// Create correlated packets
			for j := 0; j < 2; j++ {
				packet := LivePacket{
					Timestamp: time.Now(),
					PointID:   fmt.Sprintf("point%d", j+1),
					FlowKey:   flowKey,
					Data: types.PacketInfo{
						IPID: uint16(1000 + id), // Same IPID for correlation
					},
				}

				err := correlator.ProcessPacket(packet)
				if err != nil {
					t.Errorf("Failed to process packet: %v", err)
				}
				time.Sleep(time.Millisecond) // Small delay between packets
			}
		}(i)
	}

	wg.Wait()

	mu.Lock()
	finalCorrelationCount := correlationCount
	mu.Unlock()

	t.Logf("Processed %d packets, found %d correlations", packetCount*2, finalCorrelationCount)

	stats := correlator.GetStats()
	t.Logf("Final stats: %+v", stats)

	if stats.PacketsProcessed != int64(packetCount*2) {
		t.Errorf("Expected %d packets processed, got %d", packetCount*2, stats.PacketsProcessed)
	}
}

func TestStreamingCorrelatorMultipleStrategies(t *testing.T) {
	config := StreamingCorrelatorConfig{
		WindowSize: time.Second * 3,
		MaxFlows:   100,
		CorrelationMethods: []string{"ipid", "payload_hash", "tcp_sequence"},
		MinConfidence: 0.6,
	}

	correlator := NewStreamingCorrelator(config)
	defer correlator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	err := correlator.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start correlator: %v", err)
	}
	defer correlator.Stop()

	flowKey := types.NewFlowKey("tcp", net.ParseIP("192.168.1.1"), 80, net.ParseIP("10.0.0.1"), 443)

	// Create packets that match multiple correlation strategies
	packet1 := LivePacket{
		Timestamp: time.Now(),
		PointID:   "point1",
		FlowKey:   flowKey,
		Data: types.PacketInfo{
			IPID:        12345,    // IP ID correlation
			TCPSeq:      1000,     // TCP sequence correlation
			PayloadHash: "abc123", // Payload hash correlation
		},
	}

	packet2 := LivePacket{
		Timestamp: time.Now().Add(time.Millisecond * 50),
		PointID:   "point2",
		FlowKey:   flowKey,
		Data: types.PacketInfo{
			IPID:        12345,    // Same IP ID
			TCPSeq:      1000,     // Same TCP sequence
			PayloadHash: "abc123", // Same payload hash
		},
	}

	err = correlator.ProcessPacket(packet1)
	if err != nil {
		t.Errorf("Failed to process packet1: %v", err)
	}

	err = correlator.ProcessPacket(packet2)
	if err != nil {
		t.Errorf("Failed to process packet2: %v", err)
	}

	// Wait for correlation with multiple strategies
	timeout := time.After(time.Second * 2)
	select {
	case correlation := <-correlator.Correlations():
		if correlation.FlowKey != flowKey {
			t.Errorf("Unexpected flow key in correlation")
		}
		
		// Should have high confidence due to multiple matching strategies
		if correlation.Confidence < 0.8 {
			t.Errorf("Expected high confidence due to multiple strategies, got %f", correlation.Confidence)
		}

		if len(correlation.Methods) < 2 {
			t.Errorf("Expected multiple correlation methods, got %v", correlation.Methods)
		}

		t.Logf("Multi-strategy correlation: %+v", correlation)
	case <-timeout:
		t.Error("Expected correlation with multiple strategies")
	}
}

func TestStreamingCorrelatorMetrics(t *testing.T) {
	config := StreamingCorrelatorConfig{
		WindowSize: time.Second * 3,
		MaxFlows:   100,
	}

	correlator := NewStreamingCorrelator(config)
	defer correlator.Close()

	// Test initial metrics
	stats := correlator.GetStats()
	if stats.PacketsProcessed != 0 {
		t.Errorf("Expected 0 packets processed initially, got %d", stats.PacketsProcessed)
	}

	if stats.ActiveFlows != 0 {
		t.Errorf("Expected 0 active flows initially, got %d", stats.ActiveFlows)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	err := correlator.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start correlator: %v", err)
	}
	defer correlator.Stop()

	// Process some packets
	flowKey := types.NewFlowKey("tcp", net.ParseIP("192.168.1.1"), 80, net.ParseIP("10.0.0.1"), 443)
	
	for i := 0; i < 5; i++ {
		packet := LivePacket{
			Timestamp: time.Now(),
			PointID:   fmt.Sprintf("point%d", i%2+1),
			FlowKey:   flowKey,
			Data: types.PacketInfo{
				IPID: uint16(1000 + i),
			},
		}

		err = correlator.ProcessPacket(packet)
		if err != nil {
			t.Errorf("Failed to process packet: %v", err)
		}
	}

	// Wait a bit for processing
	time.Sleep(time.Millisecond * 100)

	// Check updated metrics
	stats = correlator.GetStats()
	if stats.PacketsProcessed != 5 {
		t.Errorf("Expected 5 packets processed, got %d", stats.PacketsProcessed)
	}

	if stats.ActiveFlows == 0 {
		t.Error("Expected some active flows")
	}

	t.Logf("Processing metrics: %+v", stats)
}