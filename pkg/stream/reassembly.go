package stream

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/janus-project/janus/pkg/types"
)

// StreamData represents reassembled TCP stream data
type StreamData struct {
	FlowKey      types.FlowKey
	PointID      string
	FirstSeen    time.Time
	LastSeen     time.Time
	PayloadHash  string
	PayloadSize  int
	Packets      int
	TCPSeqStart  uint32
	TCPSeqEnd    uint32
}

// StreamCollector collects reassembled stream data
type StreamCollector struct {
	streams map[types.FlowKey]*StreamData
	pointID string
	mu      sync.Mutex
}

// NewStreamCollector creates a new stream collector
func NewStreamCollector(pointID string) *StreamCollector {
	return &StreamCollector{
		streams: make(map[types.FlowKey]*StreamData),
		pointID: pointID,
	}
}

// GetStreams returns all collected streams
func (sc *StreamCollector) GetStreams() map[types.FlowKey]*StreamData {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	
	// Return a copy to avoid concurrent access
	result := make(map[types.FlowKey]*StreamData)
	for k, v := range sc.streams {
		result[k] = v
	}
	return result
}

// tcpStream handles reassembly of TCP streams
type tcpStream struct {
	net, transport gopacket.Flow
	flowKey        types.FlowKey
	collector      *StreamCollector
	hasher         hash.Hash
	firstSeen      time.Time
	lastSeen       time.Time
	payloadSize    int
	packets        int
	tcpSeqStart    uint32
	tcpSeqEnd      uint32
	seqInitialized bool
}

// Reassembled implements tcpassembly.Stream interface
func (t *tcpStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	for _, reassembly := range reassemblies {
		if reassembly.Skip > 0 {
			// Handle missing data
			continue
		}
		
		data := reassembly.Bytes
		if len(data) == 0 {
			continue
		}
		
		// Update stream statistics
		t.packets++
		t.payloadSize += len(data)
		t.lastSeen = time.Now() // tcpassembly doesn't provide timestamp in this method
		
		// Hash the payload data
		if t.hasher != nil {
			t.hasher.Write(data)
		}
	}
}

// ReassemblyComplete implements tcpassembly.Stream interface
func (t *tcpStream) ReassemblyComplete() {
	// Calculate final hash
	var hash string
	if t.hasher != nil {
		hash = hex.EncodeToString(t.hasher.Sum(nil))
	}
	
	// Store the stream data
	t.collector.mu.Lock()
	defer t.collector.mu.Unlock()
	
	t.collector.streams[t.flowKey] = &StreamData{
		FlowKey:     t.flowKey,
		PointID:     t.collector.pointID,
		FirstSeen:   t.firstSeen,
		LastSeen:    t.lastSeen,
		PayloadHash: hash,
		PayloadSize: t.payloadSize,
		Packets:     t.packets,
		TCPSeqStart: t.tcpSeqStart,
		TCPSeqEnd:   t.tcpSeqEnd,
	}
}

// tcpStreamFactory creates new TCP streams for the assembler
type tcpStreamFactory struct {
	collector *StreamCollector
}

// New implements tcpassembly.StreamFactory
func (f *tcpStreamFactory) New(netFlow, transport gopacket.Flow) tcpassembly.Stream {
	// Parse IP addresses
	srcIP := net.ParseIP(netFlow.Src().String())
	dstIP := net.ParseIP(netFlow.Dst().String())
	
	// Parse ports
	srcPort := uint16(binary.BigEndian.Uint16(transport.Src().Raw()))
	dstPort := uint16(binary.BigEndian.Uint16(transport.Dst().Raw()))
	
	flowKey := types.NewFlowKey("tcp", srcIP, srcPort, dstIP, dstPort)
	
	hasher := sha256.New()
	stream := &tcpStream{
		net:       netFlow,
		transport: transport,
		flowKey:   flowKey,
		collector: f.collector,
		hasher:    hasher,
		firstSeen: time.Now(),
		lastSeen:  time.Now(),
	}
	
	return stream
}

// StreamReassembler handles TCP stream reassembly for a capture point
type StreamReassembler struct {
	assembler *tcpassembly.Assembler
	collector *StreamCollector
	pointID   string
}

// NewStreamReassembler creates a new stream reassembler
func NewStreamReassembler(pointID string) *StreamReassembler {
	collector := NewStreamCollector(pointID)
	factory := &tcpStreamFactory{collector: collector}
	assembler := tcpassembly.NewAssembler(tcpassembly.NewStreamPool(factory))
	
	// Configure assembler for better reassembly
	assembler.MaxBufferedPagesPerConnection = 16
	assembler.MaxBufferedPagesTotal = 1024
	
	return &StreamReassembler{
		assembler: assembler,
		collector: collector,
		pointID:   pointID,
	}
}

// ProcessPacket processes a packet for stream reassembly
func (sr *StreamReassembler) ProcessPacket(packet gopacket.Packet) {
	// Only process TCP packets
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		
		// Let the assembler handle this packet
		sr.assembler.AssembleWithTimestamp(
			packet.NetworkLayer().NetworkFlow(),
			tcp,
			packet.Metadata().Timestamp,
		)
	}
}

// FlushAll flushes all pending reassembly
func (sr *StreamReassembler) FlushAll() {
	sr.assembler.FlushOlderThan(time.Now())
}

// GetStreams returns all reassembled streams
func (sr *StreamReassembler) GetStreams() map[types.FlowKey]*StreamData {
	return sr.collector.GetStreams()
}