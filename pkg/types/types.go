package types

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// FlowKey uniquely identifies a network flow using the 5-tuple
type FlowKey string

// NewFlowKey creates a flow key from the 5-tuple components
func NewFlowKey(proto string, srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) FlowKey {
	return FlowKey(fmt.Sprintf("%s:%s:%d->%s:%d", proto, srcIP, srcPort, dstIP, dstPort))
}

// Protocol extracts the protocol from the flow key
func (fk FlowKey) Protocol() string {
	str := string(fk)
	for i, ch := range str {
		if ch == ':' {
			return str[:i]
		}
	}
	return ""
}

// SrcIP extracts the source IP from the flow key
func (fk FlowKey) SrcIP() net.IP {
	str := string(fk)
	start := len(fk.Protocol()) + 1
	for i := start; i < len(str); i++ {
		if str[i] == ':' {
			return net.ParseIP(str[start:i])
		}
	}
	return nil
}

// SrcPort extracts the source port from the flow key
func (fk FlowKey) SrcPort() uint16 {
	str := string(fk)
	// Find second colon
	colonCount := 0
	start := 0
	for i, ch := range str {
		if ch == ':' {
			colonCount++
			if colonCount == 2 {
				start = i + 1
			} else if colonCount == 3 {
				// Parse port between second and third colon
				var port uint16
				fmt.Sscanf(str[start:i], "%d", &port)
				return port
			}
		}
	}
	return 0
}

// DstIP extracts the destination IP from the flow key
func (fk FlowKey) DstIP() net.IP {
	str := string(fk)
	// Find "->"
	arrowIdx := -1
	for i := 0; i < len(str)-1; i++ {
		if str[i] == '-' && str[i+1] == '>' {
			arrowIdx = i + 2
			break
		}
	}
	if arrowIdx == -1 {
		return nil
	}
	// Find colon after arrow
	for i := arrowIdx; i < len(str); i++ {
		if str[i] == ':' {
			return net.ParseIP(str[arrowIdx:i])
		}
	}
	return nil
}

// DstPort extracts the destination port from the flow key
func (fk FlowKey) DstPort() uint16 {
	str := string(fk)
	// Find last colon
	lastColon := -1
	for i := len(str) - 1; i >= 0; i-- {
		if str[i] == ':' {
			lastColon = i
			break
		}
	}
	if lastColon == -1 {
		return 0
	}
	var port uint16
	fmt.Sscanf(str[lastColon+1:], "%d", &port)
	return port
}

// PacketInfo holds the identifying characteristics of a packet at a specific point
type PacketInfo struct {
	Timestamp   time.Time
	IPID        uint16
	TCPSeq      uint32
	TCPAck      uint32
	PayloadHash string
	TTL         uint8
	SrcIP       net.IP
	DstIP       net.IP
	SrcPort     uint16
	DstPort     uint16
	Protocol    string // "tcp", "udp", etc.
}

// CapturePointInfo represents a packet's observation at one capture point
type CapturePointInfo struct {
	PointID string // User-defined name for the capture file
	Packet  PacketInfo
}

// FlowTrace tracks a single flow across all capture points
type FlowTrace struct {
	Path []CapturePointInfo // Ordered slice representing the packet's journey
	mu   sync.Mutex
}

// AddObservation adds a new packet observation to the flow trace
func (ft *FlowTrace) AddObservation(point CapturePointInfo) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	ft.Path = append(ft.Path, point)
}

// GetPath returns a copy of the current path
func (ft *FlowTrace) GetPath() []CapturePointInfo {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	path := make([]CapturePointInfo, len(ft.Path))
	copy(path, ft.Path)
	return path
}