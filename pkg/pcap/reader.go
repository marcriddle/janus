package pcap

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/janus-project/janus/pkg/types"
)

// Reader handles PCAP file reading and packet extraction
type Reader struct {
	handle   *pcap.Handle
	source   *gopacket.PacketSource
	pointID  string
	packets  chan *types.CapturePointInfo
	errors   chan error
}

// NewReader creates a new PCAP reader for the given file
func NewReader(filename string, pointID string) (*Reader, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap file %s: %w", filename, err)
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	
	return &Reader{
		handle:  handle,
		source:  source,
		pointID: pointID,
		packets: make(chan *types.CapturePointInfo, 100),
		errors:  make(chan error, 10),
	}, nil
}

// Start begins reading packets from the PCAP file
func (r *Reader) Start() {
	go r.readPackets()
}

// Packets returns the channel for receiving parsed packets
func (r *Reader) Packets() <-chan *types.CapturePointInfo {
	return r.packets
}

// Errors returns the channel for receiving errors
func (r *Reader) Errors() <-chan error {
	return r.errors
}

// Close closes the PCAP handle and channels
func (r *Reader) Close() {
	if r.handle != nil {
		r.handle.Close()
	}
	close(r.packets)
	close(r.errors)
}

func (r *Reader) readPackets() {
	defer r.Close()

	for packet := range r.source.Packets() {
		if packet.ErrorLayer() != nil {
			r.errors <- fmt.Errorf("error decoding packet: %v", packet.ErrorLayer().Error())
			continue
		}

		info := r.extractPacketInfo(packet)
		if info != nil {
			r.packets <- &types.CapturePointInfo{
				PointID: r.pointID,
				Packet:  *info,
			}
		}
	}
}

func (r *Reader) extractPacketInfo(packet gopacket.Packet) *types.PacketInfo {
	info := &types.PacketInfo{
		Timestamp: packet.Metadata().Timestamp,
	}

	// Extract IPv4 layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, ok := ipLayer.(*layers.IPv4)
		if !ok {
			return nil
		}
		info.SrcIP = ip.SrcIP
		info.DstIP = ip.DstIP
		info.IPID = ip.Id
		info.TTL = ip.TTL
		info.Protocol = ip.Protocol.String()
	} else {
		// For Phase 1, we only support IPv4
		return nil
	}

	// Extract TCP layer if present
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			return nil
		}
		info.SrcPort = uint16(tcp.SrcPort)
		info.DstPort = uint16(tcp.DstPort)
		info.TCPSeq = tcp.Seq
		info.TCPAck = tcp.Ack
		info.Protocol = "tcp"
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, ok := udpLayer.(*layers.UDP)
		if !ok {
			return nil
		}
		info.SrcPort = uint16(udp.SrcPort)
		info.DstPort = uint16(udp.DstPort)
		info.Protocol = "udp"
	}

	return info
}

// ReadAllPackets reads all packets from a PCAP file synchronously
func ReadAllPackets(filename string, pointID string) ([]*types.CapturePointInfo, error) {
	reader, err := NewReader(filename, pointID)
	if err != nil {
		return nil, err
	}

	reader.Start()

	var packets []*types.CapturePointInfo
	for {
		select {
		case pkt, ok := <-reader.Packets():
			if !ok {
				return packets, nil
			}
			packets = append(packets, pkt)
		case err := <-reader.Errors():
			log.Printf("Warning: error reading packet: %v", err)
		}
	}
}