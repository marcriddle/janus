package nat

import (
	"fmt"
	"sync"
	"time"

	"github.com/janus-project/janus/pkg/types"
)

// ConnectionTracker tracks stateful connections through NAT devices
type ConnectionTracker struct {
	// Active connections indexed by flow key
	connections map[types.FlowKey]*Connection
	
	// Timeout settings
	tcpTimeout time.Duration
	udpTimeout time.Duration
	
	// Statistics
	stats TrackerStats
	
	mu sync.RWMutex
}

// Connection represents a tracked connection
type Connection struct {
	// Connection identifiers
	OriginalFlow   types.FlowKey
	TranslatedFlow types.FlowKey
	
	// Connection state
	State         ConnectionState
	Protocol      string
	
	// Timestamps
	Created       time.Time
	LastActivity  time.Time
	StateChanged  time.Time
	
	// TCP specific
	TCPState      TCPState
	SYNSeen       bool
	FINSeen       bool
	RSTSeen       bool
	
	// Statistics
	PacketsForward  int64
	PacketsReverse  int64
	BytesForward    int64
	BytesReverse    int64
	
	// NAT behavior
	NATType         TransformationType
	PortPreservation bool
	Symmetric        bool
}

// TCPState represents TCP connection states
type TCPState int

const (
	TCPStateNone TCPState = iota
	TCPStateSYNSent
	TCPStateSYNReceived
	TCPStateEstablished
	TCPStateFinWait1
	TCPStateFinWait2
	TCPStateTimeWait
	TCPStateClose
	TCPStateCloseWait
	TCPStateLastAck
	TCPStateClosing
)

// TrackerStats holds connection tracking statistics
type TrackerStats struct {
	ActiveConnections   int64
	TotalConnections    int64
	ExpiredConnections  int64
	TCPConnections      int64
	UDPConnections      int64
	SymmetricNATFlows   int64
	AsymmetricNATFlows  int64
}

// NewConnectionTracker creates a new connection tracker
func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{
		connections: make(map[types.FlowKey]*Connection),
		tcpTimeout:  5 * time.Minute,
		udpTimeout:  30 * time.Second,
	}
}

// TrackPacket updates connection state based on a packet
func (ct *ConnectionTracker) TrackPacket(pkt *types.CapturePointInfo, natEntry *NATEntry) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	
	flow := types.NewFlowKey(pkt.Packet.Protocol, pkt.Packet.SrcIP, pkt.Packet.SrcPort,
		pkt.Packet.DstIP, pkt.Packet.DstPort)
	
	// Look for existing connection
	conn, exists := ct.connections[flow]
	if !exists {
		// Check reverse flow
		reverseFlow := types.NewFlowKey(pkt.Packet.Protocol, pkt.Packet.DstIP, pkt.Packet.DstPort,
			pkt.Packet.SrcIP, pkt.Packet.SrcPort)
		conn, exists = ct.connections[reverseFlow]
		
		if !exists && natEntry != nil {
			// New connection
			conn = ct.createConnection(flow, natEntry)
			ct.connections[flow] = conn
			ct.stats.TotalConnections++
			ct.stats.ActiveConnections++
			
			if pkt.Packet.Protocol == "tcp" {
				ct.stats.TCPConnections++
			} else if pkt.Packet.Protocol == "udp" {
				ct.stats.UDPConnections++
			}
		}
	}
	
	if conn != nil {
		ct.updateConnection(conn, pkt)
	}
}

// createConnection creates a new connection entry
func (ct *ConnectionTracker) createConnection(flow types.FlowKey, natEntry *NATEntry) *Connection {
	conn := &Connection{
		OriginalFlow:   flow,
		TranslatedFlow: natEntry.GetTranslatedFlow(),
		State:          StateNew,
		Protocol:       natEntry.Protocol,
		Created:        time.Now(),
		LastActivity:   time.Now(),
		StateChanged:   time.Now(),
		NATType:        natEntry.TransformType,
		
		// Check if ports are preserved
		PortPreservation: natEntry.OriginalSrcPort == natEntry.TranslatedSrcPort,
	}
	
	if conn.Protocol == "tcp" {
		conn.TCPState = TCPStateNone
	}
	
	return conn
}

// updateConnection updates connection state based on packet
func (ct *ConnectionTracker) updateConnection(conn *Connection, pkt *types.CapturePointInfo) {
	conn.LastActivity = pkt.Packet.Timestamp
	
	// Determine direction
	isForward := conn.OriginalFlow == types.NewFlowKey(pkt.Packet.Protocol, 
		pkt.Packet.SrcIP, pkt.Packet.SrcPort, pkt.Packet.DstIP, pkt.Packet.DstPort)
	
	if isForward {
		conn.PacketsForward++
		// Note: Real implementation would extract payload size
		conn.BytesForward += 1500 // Placeholder
	} else {
		conn.PacketsReverse++
		conn.BytesReverse += 1500 // Placeholder
		if !conn.Symmetric {
			conn.Symmetric = true
			ct.stats.SymmetricNATFlows++
		}
	}
	
	// Update TCP state if applicable
	if conn.Protocol == "tcp" && pkt.Packet.Protocol == "tcp" {
		ct.updateTCPState(conn, pkt)
	}
	
	// Update connection state
	if conn.State == StateNew && conn.Symmetric {
		conn.State = StateEstablished
		conn.StateChanged = pkt.Packet.Timestamp
	}
}

// updateTCPState updates TCP-specific connection state
func (ct *ConnectionTracker) updateTCPState(conn *Connection, pkt *types.CapturePointInfo) {
	// This is a simplified TCP state machine
	// Real implementation would need full TCP flag analysis
	
	oldState := conn.TCPState
	
	switch conn.TCPState {
	case TCPStateNone:
		conn.TCPState = TCPStateSYNSent
		conn.SYNSeen = true
		
	case TCPStateSYNSent:
		if conn.Symmetric {
			conn.TCPState = TCPStateEstablished
		}
		
	case TCPStateEstablished:
		// Check for connection termination
		// In real implementation, would check FIN/RST flags
		
	default:
		// Handle other states
	}
	
	if oldState != conn.TCPState {
		conn.StateChanged = pkt.Packet.Timestamp
	}
}

// ExpireConnections removes timed-out connections
func (ct *ConnectionTracker) ExpireConnections() {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	
	now := time.Now()
	expired := []types.FlowKey{}
	
	for flow, conn := range ct.connections {
		var timeout time.Duration
		if conn.Protocol == "tcp" {
			timeout = ct.tcpTimeout
		} else {
			timeout = ct.udpTimeout
		}
		
		if now.Sub(conn.LastActivity) > timeout {
			expired = append(expired, flow)
		}
	}
	
	// Remove expired connections
	for _, flow := range expired {
		delete(ct.connections, flow)
		ct.stats.ActiveConnections--
		ct.stats.ExpiredConnections++
	}
}

// GetConnection retrieves connection information
func (ct *ConnectionTracker) GetConnection(flow types.FlowKey) (*Connection, bool) {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	
	conn, exists := ct.connections[flow]
	
	return conn, exists
}

// GetStats returns current tracker statistics
func (ct *ConnectionTracker) GetStats() TrackerStats {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.stats
}

// AnalyzeNATBehavior analyzes NAT behavior patterns
func (ct *ConnectionTracker) AnalyzeNATBehavior() *NATBehaviorAnalysis {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	
	analysis := &NATBehaviorAnalysis{
		TotalConnections:     ct.stats.TotalConnections,
		ActiveConnections:    ct.stats.ActiveConnections,
		PortPreservation:     0,
		SymmetricBehavior:    0,
		NATTypes:             make(map[TransformationType]int64),
		AverageConnectionDur: 0,
		Findings:             []string{},
	}
	
	var totalDuration time.Duration
	var connectionCount int64
	
	for _, conn := range ct.connections {
		// Port preservation analysis
		if conn.PortPreservation {
			analysis.PortPreservation++
		}
		
		// Symmetric behavior
		if conn.Symmetric {
			analysis.SymmetricBehavior++
		}
		
		// NAT type distribution
		analysis.NATTypes[conn.NATType]++
		
		// Connection duration
		duration := conn.LastActivity.Sub(conn.Created)
		totalDuration += duration
		connectionCount++
	}
	
	// Calculate averages
	if connectionCount > 0 {
		analysis.AverageConnectionDur = totalDuration / time.Duration(connectionCount)
	}
	
	// Generate findings
	analysis.Findings = ct.generateBehaviorFindings(analysis)
	
	return analysis
}

// generateBehaviorFindings creates insights about NAT behavior
func (ct *ConnectionTracker) generateBehaviorFindings(analysis *NATBehaviorAnalysis) []string {
	findings := []string{}
	
	// Port preservation analysis
	if analysis.TotalConnections > 0 {
		portPreservationRate := float64(analysis.PortPreservation) / float64(analysis.TotalConnections) * 100
		if portPreservationRate > 80 {
			findings = append(findings, fmt.Sprintf("High port preservation rate (%.1f%%) - indicates endpoint-independent NAT", 
				portPreservationRate))
		} else if portPreservationRate < 20 {
			findings = append(findings, fmt.Sprintf("Low port preservation rate (%.1f%%) - indicates symmetric NAT", 
				portPreservationRate))
		}
	}
	
	// NAT type analysis
	for natType, count := range analysis.NATTypes {
		percentage := float64(count) / float64(analysis.TotalConnections) * 100
		if percentage > 50 {
			findings = append(findings, fmt.Sprintf("Predominantly %s behavior (%.1f%% of connections)", 
				natType, percentage))
		}
	}
	
	// Connection duration insights
	if analysis.AverageConnectionDur > 5*time.Minute {
		findings = append(findings, fmt.Sprintf("Long-lived connections detected (avg: %v) - stateful firewall present", 
			analysis.AverageConnectionDur))
	} else if analysis.AverageConnectionDur < 30*time.Second {
		findings = append(findings, fmt.Sprintf("Short-lived connections (avg: %v) - possible aggressive timeouts", 
			analysis.AverageConnectionDur))
	}
	
	// Symmetric behavior
	if analysis.TotalConnections > 0 {
		symmetricRate := float64(analysis.SymmetricBehavior) / float64(analysis.TotalConnections) * 100
		findings = append(findings, fmt.Sprintf("%.1f%% of connections show bidirectional traffic", symmetricRate))
	}
	
	return findings
}

// NATBehaviorAnalysis contains NAT behavior analysis results
type NATBehaviorAnalysis struct {
	TotalConnections     int64
	ActiveConnections    int64
	PortPreservation     int64
	SymmetricBehavior    int64
	NATTypes             map[TransformationType]int64
	AverageConnectionDur time.Duration
	Findings             []string
}

