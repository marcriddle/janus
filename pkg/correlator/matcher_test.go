package correlator

import (
	"net"
	"testing"
	"time"

	"github.com/janus-project/janus/pkg/types"
)

func TestPacketMatcher_IPIDMatching(t *testing.T) {
	matcher := NewPacketMatcher()
	
	p1 := &types.CapturePointInfo{
		PointID: "point1",
		Packet: types.PacketInfo{
			Timestamp: time.Now(),
			IPID:      12345,
			SrcIP:     net.ParseIP("192.168.1.10"),
			DstIP:     net.ParseIP("10.0.0.1"),
			SrcPort:   54321,
			DstPort:   80,
			Protocol:  "tcp",
			TTL:       64,
		},
	}
	
	p2 := &types.CapturePointInfo{
		PointID: "point2",
		Packet: types.PacketInfo{
			Timestamp: time.Now().Add(5 * time.Millisecond),
			IPID:      12345,
			SrcIP:     net.ParseIP("192.168.1.10"),
			DstIP:     net.ParseIP("10.0.0.1"),
			SrcPort:   54321,
			DstPort:   80,
			Protocol:  "tcp",
			TTL:       63,
		},
	}
	
	result := matcher.Match(p1, p2, nil)
	
	if !result.Matched {
		t.Error("Expected packets to match by IP ID")
	}
	
	if result.Strategy != MatchIPID {
		t.Errorf("Expected MatchIPID strategy, got %v", result.Strategy)
	}
	
	if result.Confidence < 0.5 {
		t.Errorf("Expected confidence > 0.5, got %f", result.Confidence)
	}
}

func TestPacketMatcher_TCPSeqMatching(t *testing.T) {
	matcher := NewPacketMatcher()
	
	p1 := &types.CapturePointInfo{
		PointID: "point1",
		Packet: types.PacketInfo{
			Timestamp: time.Now(),
			IPID:      0, // No IP ID
			SrcIP:     net.ParseIP("192.168.1.10"),
			DstIP:     net.ParseIP("10.0.0.1"),
			SrcPort:   54321,
			DstPort:   80,
			Protocol:  "tcp",
			TCPSeq:    1000,
			TTL:       64,
		},
	}
	
	p2 := &types.CapturePointInfo{
		PointID: "point2",
		Packet: types.PacketInfo{
			Timestamp: time.Now().Add(5 * time.Millisecond),
			IPID:      0,
			SrcIP:     net.ParseIP("192.168.1.10"),
			DstIP:     net.ParseIP("10.0.0.1"),
			SrcPort:   54321,
			DstPort:   80,
			Protocol:  "tcp",
			TCPSeq:    1000,
			TTL:       63,
		},
	}
	
	result := matcher.Match(p1, p2, nil)
	
	if !result.Matched {
		t.Error("Expected packets to match by TCP sequence")
	}
	
	if result.Strategy != MatchTCPSeq {
		t.Errorf("Expected MatchTCPSeq strategy, got %v", result.Strategy)
	}
}

func TestPacketMatcher_PayloadHashMatching(t *testing.T) {
	matcher := NewPacketMatcher()
	
	flow := types.NewFlowKey("tcp", net.ParseIP("192.168.1.10"), 54321, net.ParseIP("10.0.0.1"), 80)
	hash := "d2d2d2d2d2d2d2d2"
	
	streamData := map[types.FlowKey]string{
		flow: hash,
	}
	
	p1 := &types.CapturePointInfo{
		PointID: "point1",
		Packet: types.PacketInfo{
			Timestamp: time.Now(),
			SrcIP:     net.ParseIP("192.168.1.10"),
			DstIP:     net.ParseIP("10.0.0.1"),
			SrcPort:   54321,
			DstPort:   80,
			Protocol:  "tcp",
		},
	}
	
	p2 := &types.CapturePointInfo{
		PointID: "point2",
		Packet: types.PacketInfo{
			Timestamp: time.Now().Add(5 * time.Millisecond),
			SrcIP:     net.ParseIP("192.168.1.10"),
			DstIP:     net.ParseIP("10.0.0.1"),
			SrcPort:   54321,
			DstPort:   80,
			Protocol:  "tcp",
		},
	}
	
	result := matcher.Match(p1, p2, streamData)
	
	if !result.Matched {
		t.Error("Expected packets to match by payload hash")
	}
	
	if result.Strategy != MatchPayloadHash {
		t.Errorf("Expected MatchPayloadHash strategy, got %v", result.Strategy)
	}
	
	if result.Confidence < 0.9 {
		t.Errorf("Expected high confidence for payload hash match, got %f", result.Confidence)
	}
}

func TestCombineMatches(t *testing.T) {
	primary := MatchResult{
		Matched:     true,
		Strategy:    MatchIPID,
		Confidence:  0.7,
		Description: "IP ID match",
	}
	
	secondary := MatchResult{
		Matched:     true,
		Strategy:    MatchTTLPattern,
		Confidence:  0.3,
		Description: "TTL pattern match",
	}
	
	combined := CombineMatches(primary, secondary)
	
	if !combined.Matched {
		t.Error("Combined match should be matched")
	}
	
	expectedConfidence := 0.7 + (0.3 * 0.1) // 0.73
	if combined.Confidence != expectedConfidence {
		t.Errorf("Expected confidence %f, got %f", expectedConfidence, combined.Confidence)
	}
	
	if combined.Description != "IP ID match; TTL pattern match" {
		t.Errorf("Unexpected combined description: %s", combined.Description)
	}
}