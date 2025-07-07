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