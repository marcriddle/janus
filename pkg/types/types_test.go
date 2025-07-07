package types

import (
	"net"
	"testing"
	"time"
)

func TestNewFlowKey(t *testing.T) {
	tests := []struct {
		name     string
		proto    string
		srcIP    net.IP
		srcPort  uint16
		dstIP    net.IP
		dstPort  uint16
		expected string
	}{
		{
			name:     "TCP flow",
			proto:    "tcp",
			srcIP:    net.ParseIP("192.168.1.10"),
			srcPort:  54321,
			dstIP:    net.ParseIP("10.0.0.1"),
			dstPort:  80,
			expected: "tcp:192.168.1.10:54321->10.0.0.1:80",
		},
		{
			name:     "UDP flow",
			proto:    "udp",
			srcIP:    net.ParseIP("10.0.0.2"),
			srcPort:  53,
			dstIP:    net.ParseIP("8.8.8.8"),
			dstPort:  53,
			expected: "udp:10.0.0.2:53->8.8.8.8:53",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flowKey := NewFlowKey(tt.proto, tt.srcIP, tt.srcPort, tt.dstIP, tt.dstPort)
			if string(flowKey) != tt.expected {
				t.Errorf("NewFlowKey() = %v, want %v", flowKey, tt.expected)
			}
		})
	}
}

func TestFlowTrace(t *testing.T) {
	ft := &FlowTrace{}

	// Test adding observations
	point1 := CapturePointInfo{
		PointID: "point1",
		Packet: PacketInfo{
			Timestamp: time.Now(),
			IPID:      12345,
			SrcIP:     net.ParseIP("192.168.1.10"),
			DstIP:     net.ParseIP("10.0.0.1"),
			SrcPort:   54321,
			DstPort:   80,
		},
	}

	point2 := CapturePointInfo{
		PointID: "point2",
		Packet: PacketInfo{
			Timestamp: time.Now().Add(5 * time.Millisecond),
			IPID:      12345,
			SrcIP:     net.ParseIP("192.168.1.10"),
			DstIP:     net.ParseIP("10.0.0.1"),
			SrcPort:   54321,
			DstPort:   80,
		},
	}

	ft.AddObservation(point1)
	ft.AddObservation(point2)

	path := ft.GetPath()
	if len(path) != 2 {
		t.Errorf("GetPath() returned %d observations, want 2", len(path))
	}

	if path[0].PointID != "point1" {
		t.Errorf("First observation PointID = %v, want point1", path[0].PointID)
	}

	if path[1].PointID != "point2" {
		t.Errorf("Second observation PointID = %v, want point2", path[1].PointID)
	}
}