package nat

import (
	"net"
	"testing"
	"time"

	"github.com/janus-project/janus/pkg/types"
)

func TestConnectionTracker_TrackPacket(t *testing.T) {
	tracker := NewConnectionTracker()
	
	// Create test packet and NAT entry
	pkt := &types.CapturePointInfo{
		PointID: "test",
		Packet: types.PacketInfo{
			SrcIP:     net.ParseIP("192.168.1.100"),
			SrcPort:   45678,
			DstIP:     net.ParseIP("8.8.8.8"),
			DstPort:   443,
			Protocol:  "tcp",
			Timestamp: time.Now(),
		},
	}
	
	natEntry := &NATEntry{
		OriginalSrcIP:     net.ParseIP("192.168.1.100"),
		OriginalSrcPort:   45678,
		OriginalDstIP:     net.ParseIP("8.8.8.8"),
		OriginalDstPort:   443,
		TranslatedSrcIP:   net.ParseIP("203.0.113.1"),
		TranslatedSrcPort: 23456,
		TranslatedDstIP:   net.ParseIP("8.8.8.8"),
		TranslatedDstPort: 443,
		Protocol:          "tcp",
		TransformType:     SourceNAT,
	}
	
	// Track the packet
	tracker.TrackPacket(pkt, natEntry)
	
	// Verify connection was created
	flow := types.NewFlowKey("tcp", net.ParseIP("192.168.1.100"), 45678,
		net.ParseIP("8.8.8.8"), 443)
	
	conn, exists := tracker.GetConnection(flow)
	if !exists {
		t.Fatal("Connection not found after tracking packet")
	}
	
	if conn.Protocol != "tcp" {
		t.Errorf("Connection protocol = %s, want tcp", conn.Protocol)
	}
	
	if conn.NATType != SourceNAT {
		t.Errorf("Connection NATType = %v, want SourceNAT", conn.NATType)
	}
	
	if conn.PacketsForward != 1 {
		t.Errorf("PacketsForward = %d, want 1", conn.PacketsForward)
	}
	
	// Track reverse packet
	reversePkt := &types.CapturePointInfo{
		PointID: "test",
		Packet: types.PacketInfo{
			SrcIP:     net.ParseIP("8.8.8.8"),
			SrcPort:   443,
			DstIP:     net.ParseIP("192.168.1.100"),
			DstPort:   45678,
			Protocol:  "tcp",
			Timestamp: time.Now(),
		},
	}
	
	tracker.TrackPacket(reversePkt, natEntry)
	
	// Verify symmetric traffic detected
	conn, _ = tracker.GetConnection(flow)
	if !conn.Symmetric {
		t.Error("Connection should be marked as symmetric after reverse traffic")
	}
	
	if conn.PacketsReverse != 1 {
		t.Errorf("PacketsReverse = %d, want 1", conn.PacketsReverse)
	}
}

func TestConnectionTracker_PortPreservation(t *testing.T) {
	tests := []struct {
		name         string
		natEntry     *NATEntry
		wantPreserve bool
	}{
		{
			name: "Port preserved",
			natEntry: &NATEntry{
				OriginalSrcPort:   45678,
				TranslatedSrcPort: 45678,
			},
			wantPreserve: true,
		},
		{
			name: "Port not preserved",
			natEntry: &NATEntry{
				OriginalSrcPort:   45678,
				TranslatedSrcPort: 23456,
			},
			wantPreserve: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := NewConnectionTracker()
			pkt := &types.CapturePointInfo{
				Packet: types.PacketInfo{
					SrcIP:    net.ParseIP("192.168.1.100"),
					SrcPort:  tt.natEntry.OriginalSrcPort,
					DstIP:    net.ParseIP("8.8.8.8"),
					DstPort:  443,
					Protocol: "tcp",
				},
			}
			
			tt.natEntry.OriginalSrcIP = pkt.Packet.SrcIP
			tt.natEntry.OriginalDstIP = pkt.Packet.DstIP
			tt.natEntry.OriginalDstPort = pkt.Packet.DstPort
			tt.natEntry.TranslatedSrcIP = net.ParseIP("203.0.113.1")
			tt.natEntry.TranslatedDstIP = pkt.Packet.DstIP
			tt.natEntry.TranslatedDstPort = pkt.Packet.DstPort
			tt.natEntry.Protocol = "tcp"
			
			tracker.TrackPacket(pkt, tt.natEntry)
			
			flow := types.NewFlowKey("tcp", pkt.Packet.SrcIP, pkt.Packet.SrcPort,
				pkt.Packet.DstIP, pkt.Packet.DstPort)
			
			conn, exists := tracker.GetConnection(flow)
			if !exists {
				t.Fatal("Connection not found")
			}
			
			if conn.PortPreservation != tt.wantPreserve {
				t.Errorf("PortPreservation = %v, want %v", 
					conn.PortPreservation, tt.wantPreserve)
			}
		})
	}
}

func TestConnectionTracker_ExpireConnections(t *testing.T) {
	tracker := NewConnectionTracker()
	
	// Set short timeouts for testing
	tracker.tcpTimeout = 100 * time.Millisecond
	tracker.udpTimeout = 50 * time.Millisecond
	
	// Create old TCP connection
	tcpPkt := &types.CapturePointInfo{
		Packet: types.PacketInfo{
			SrcIP:     net.ParseIP("192.168.1.100"),
			SrcPort:   45678,
			DstIP:     net.ParseIP("8.8.8.8"),
			DstPort:   443,
			Protocol:  "tcp",
			Timestamp: time.Now().Add(-200 * time.Millisecond),
		},
	}
	
	tcpNATEntry := &NATEntry{
		OriginalSrcIP:     tcpPkt.Packet.SrcIP,
		OriginalSrcPort:   tcpPkt.Packet.SrcPort,
		OriginalDstIP:     tcpPkt.Packet.DstIP,
		OriginalDstPort:   tcpPkt.Packet.DstPort,
		TranslatedSrcIP:   net.ParseIP("203.0.113.1"),
		TranslatedSrcPort: 23456,
		TranslatedDstIP:   tcpPkt.Packet.DstIP,
		TranslatedDstPort: tcpPkt.Packet.DstPort,
		Protocol:          "tcp",
	}
	
	tracker.TrackPacket(tcpPkt, tcpNATEntry)
	
	// Create old UDP connection
	udpPkt := &types.CapturePointInfo{
		Packet: types.PacketInfo{
			SrcIP:     net.ParseIP("192.168.1.101"),
			SrcPort:   53000,
			DstIP:     net.ParseIP("8.8.4.4"),
			DstPort:   53,
			Protocol:  "udp",
			Timestamp: time.Now().Add(-100 * time.Millisecond),
		},
	}
	
	udpNATEntry := &NATEntry{
		OriginalSrcIP:     udpPkt.Packet.SrcIP,
		OriginalSrcPort:   udpPkt.Packet.SrcPort,
		OriginalDstIP:     udpPkt.Packet.DstIP,
		OriginalDstPort:   udpPkt.Packet.DstPort,
		TranslatedSrcIP:   net.ParseIP("203.0.113.1"),
		TranslatedSrcPort: 23457,
		TranslatedDstIP:   udpPkt.Packet.DstIP,
		TranslatedDstPort: udpPkt.Packet.DstPort,
		Protocol:          "udp",
	}
	
	tracker.TrackPacket(udpPkt, udpNATEntry)
	
	// Create recent connection (should not expire)
	recentPkt := &types.CapturePointInfo{
		Packet: types.PacketInfo{
			SrcIP:     net.ParseIP("192.168.1.102"),
			SrcPort:   45679,
			DstIP:     net.ParseIP("1.1.1.1"),
			DstPort:   443,
			Protocol:  "tcp",
			Timestamp: time.Now(),
		},
	}
	
	recentNATEntry := &NATEntry{
		OriginalSrcIP:     recentPkt.Packet.SrcIP,
		OriginalSrcPort:   recentPkt.Packet.SrcPort,
		OriginalDstIP:     recentPkt.Packet.DstIP,
		OriginalDstPort:   recentPkt.Packet.DstPort,
		TranslatedSrcIP:   net.ParseIP("203.0.113.1"),
		TranslatedSrcPort: 23458,
		TranslatedDstIP:   recentPkt.Packet.DstIP,
		TranslatedDstPort: recentPkt.Packet.DstPort,
		Protocol:          "tcp",
	}
	
	tracker.TrackPacket(recentPkt, recentNATEntry)
	
	// Manually update LastActivity for old connections
	tracker.mu.Lock()
	for _, conn := range tracker.connections {
		if conn.Protocol == "tcp" && conn.OriginalFlow.SrcPort() == 45678 {
			conn.LastActivity = time.Now().Add(-200 * time.Millisecond)
		} else if conn.Protocol == "udp" {
			conn.LastActivity = time.Now().Add(-100 * time.Millisecond)
		}
	}
	tracker.mu.Unlock()
	
	// Initial stats
	stats := tracker.GetStats()
	initialActive := stats.ActiveConnections
	
	// Expire connections
	tracker.ExpireConnections()
	
	// Check results
	stats = tracker.GetStats()
	if stats.ActiveConnections >= initialActive {
		t.Errorf("ActiveConnections = %d, should be less than initial %d",
			stats.ActiveConnections, initialActive)
	}
	
	if stats.ExpiredConnections == 0 {
		t.Error("ExpiredConnections = 0, expected some expired connections")
	}
	
	// Recent connection should still exist
	recentFlow := types.NewFlowKey("tcp", recentPkt.Packet.SrcIP, recentPkt.Packet.SrcPort,
		recentPkt.Packet.DstIP, recentPkt.Packet.DstPort)
	
	_, exists := tracker.GetConnection(recentFlow)
	if !exists {
		t.Error("Recent connection should not be expired")
	}
}

func TestConnectionTracker_AnalyzeNATBehavior(t *testing.T) {
	tracker := NewConnectionTracker()
	
	// Create connections with different behaviors
	connections := []struct {
		flow         types.FlowKey
		natType      TransformationType
		portPreserve bool
		symmetric    bool
		duration     time.Duration
	}{
		{
			flow: types.NewFlowKey("tcp", net.ParseIP("192.168.1.100"), 45678,
				net.ParseIP("8.8.8.8"), 443),
			natType:      SourceNAT,
			portPreserve: true,
			symmetric:    true,
			duration:     10 * time.Minute,
		},
		{
			flow: types.NewFlowKey("tcp", net.ParseIP("192.168.1.101"), 45679,
				net.ParseIP("8.8.4.4"), 443),
			natType:      SymmetricNAT,
			portPreserve: false,
			symmetric:    true,
			duration:     20 * time.Second,
		},
		{
			flow: types.NewFlowKey("udp", net.ParseIP("192.168.1.102"), 53000,
				net.ParseIP("8.8.8.8"), 53),
			natType:      SourceNAT,
			portPreserve: true,
			symmetric:    false,
			duration:     5 * time.Second,
		},
	}
	
	// Add connections to tracker
	for _, c := range connections {
		conn := &Connection{
			OriginalFlow:     c.flow,
			NATType:          c.natType,
			PortPreservation: c.portPreserve,
			Symmetric:        c.symmetric,
			Created:          time.Now().Add(-c.duration),
			LastActivity:     time.Now(),
			Protocol:         c.flow.Protocol(),
		}
		tracker.mu.Lock()
		tracker.connections[c.flow] = conn
		tracker.stats.TotalConnections++
		tracker.stats.ActiveConnections++
		if c.symmetric {
			tracker.stats.SymmetricNATFlows++
		}
		tracker.mu.Unlock()
	}
	
	// Analyze behavior
	analysis := tracker.AnalyzeNATBehavior()
	
	if analysis.TotalConnections != 3 {
		t.Errorf("TotalConnections = %d, want 3", analysis.TotalConnections)
	}
	
	if analysis.PortPreservation != 2 {
		t.Errorf("PortPreservation = %d, want 2", analysis.PortPreservation)
	}
	
	if analysis.SymmetricBehavior != 2 {
		t.Errorf("SymmetricBehavior = %d, want 2", analysis.SymmetricBehavior)
	}
	
	// Check NAT type distribution
	if analysis.NATTypes[SourceNAT] != 2 {
		t.Errorf("SourceNAT count = %d, want 2", analysis.NATTypes[SourceNAT])
	}
	
	if analysis.NATTypes[SymmetricNAT] != 1 {
		t.Errorf("SymmetricNAT count = %d, want 1", analysis.NATTypes[SymmetricNAT])
	}
	
	// Check findings
	if len(analysis.Findings) == 0 {
		t.Error("Expected behavior analysis to generate findings")
	}
	
	// Look for specific findings
	foundNATType := false
	foundBidirectional := false
	for _, finding := range analysis.Findings {
		if contains(finding, "Predominantly") {
			foundNATType = true
		}
		if contains(finding, "bidirectional traffic") {
			foundBidirectional = true
		}
	}
	
	if !foundNATType {
		t.Error("Expected finding about predominant NAT type")
	}
	
	if !foundBidirectional {
		t.Error("Expected finding about bidirectional traffic")
	}
}

func TestConnectionTracker_TCPState(t *testing.T) {
	tracker := NewConnectionTracker()
	
	pkt := &types.CapturePointInfo{
		Packet: types.PacketInfo{
			SrcIP:     net.ParseIP("192.168.1.100"),
			SrcPort:   45678,
			DstIP:     net.ParseIP("8.8.8.8"),
			DstPort:   443,
			Protocol:  "tcp",
			Timestamp: time.Now(),
		},
	}
	
	natEntry := &NATEntry{
		OriginalSrcIP:     pkt.Packet.SrcIP,
		OriginalSrcPort:   pkt.Packet.SrcPort,
		OriginalDstIP:     pkt.Packet.DstIP,
		OriginalDstPort:   pkt.Packet.DstPort,
		TranslatedSrcIP:   net.ParseIP("203.0.113.1"),
		TranslatedSrcPort: 23456,
		TranslatedDstIP:   pkt.Packet.DstIP,
		TranslatedDstPort: pkt.Packet.DstPort,
		Protocol:          "tcp",
		TransformType:     SourceNAT,
	}
	
	// Track initial packet
	tracker.TrackPacket(pkt, natEntry)
	
	flow := types.NewFlowKey("tcp", pkt.Packet.SrcIP, pkt.Packet.SrcPort,
		pkt.Packet.DstIP, pkt.Packet.DstPort)
	
	conn, _ := tracker.GetConnection(flow)
	if conn.TCPState != TCPStateSYNSent {
		t.Errorf("Initial TCP state = %v, want TCPStateSYNSent", conn.TCPState)
	}
	
	// Track return packet to establish connection
	returnPkt := &types.CapturePointInfo{
		Packet: types.PacketInfo{
			SrcIP:     pkt.Packet.DstIP,
			SrcPort:   pkt.Packet.DstPort,
			DstIP:     pkt.Packet.SrcIP,
			DstPort:   pkt.Packet.SrcPort,
			Protocol:  "tcp",
			Timestamp: time.Now(),
		},
	}
	
	tracker.TrackPacket(returnPkt, natEntry)
	
	conn, _ = tracker.GetConnection(flow)
	if conn.TCPState != TCPStateEstablished {
		t.Errorf("TCP state after symmetric traffic = %v, want TCPStateEstablished", 
			conn.TCPState)
	}
	
	if conn.State != StateEstablished {
		t.Errorf("Connection state = %v, want StateEstablished", conn.State)
	}
}