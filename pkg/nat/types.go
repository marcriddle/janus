package nat

import (
	"fmt"
	"net"
	"time"

	"github.com/janus-project/janus/pkg/types"
)

// TransformationType represents different types of NAT transformations
type TransformationType int

const (
	// NoTransformation indicates no NAT occurred
	NoTransformation TransformationType = iota
	// SourceNAT indicates source address/port translation
	SourceNAT
	// DestinationNAT indicates destination address/port translation
	DestinationNAT
	// FullConeNAT indicates full cone NAT (1:1 mapping)
	FullConeNAT
	// RestrictedConeNAT indicates restricted cone NAT
	RestrictedConeNAT
	// PortRestrictedConeNAT indicates port restricted cone NAT
	PortRestrictedConeNAT
	// SymmetricNAT indicates symmetric NAT
	SymmetricNAT
	// DoubleNAT indicates multiple NAT transformations
	DoubleNAT
	// CGNAT indicates carrier-grade NAT
	CGNAT
)

// String returns a human-readable name for the transformation type
func (t TransformationType) String() string {
	switch t {
	case NoTransformation:
		return "None"
	case SourceNAT:
		return "Source NAT"
	case DestinationNAT:
		return "Destination NAT"
	case FullConeNAT:
		return "Full Cone NAT"
	case RestrictedConeNAT:
		return "Restricted Cone NAT"
	case PortRestrictedConeNAT:
		return "Port Restricted Cone NAT"
	case SymmetricNAT:
		return "Symmetric NAT"
	case DoubleNAT:
		return "Double NAT"
	case CGNAT:
		return "Carrier-Grade NAT"
	default:
		return "Unknown"
	}
}

// NATEntry represents a single NAT translation entry
type NATEntry struct {
	// Original (pre-NAT) addresses
	OriginalSrcIP   net.IP
	OriginalSrcPort uint16
	OriginalDstIP   net.IP
	OriginalDstPort uint16
	
	// Translated (post-NAT) addresses
	TranslatedSrcIP   net.IP
	TranslatedSrcPort uint16
	TranslatedDstIP   net.IP
	TranslatedDstPort uint16
	
	// Metadata
	Protocol         string
	TransformType    TransformationType
	FirstSeen        time.Time
	LastSeen         time.Time
	PacketCount      int64
	ByteCount        int64
	BidirectionalFlow bool
	
	// Detection confidence
	Confidence float64
}

// GetOriginalFlow returns the pre-NAT flow key
func (e *NATEntry) GetOriginalFlow() types.FlowKey {
	return types.NewFlowKey(e.Protocol, e.OriginalSrcIP, e.OriginalSrcPort, 
		e.OriginalDstIP, e.OriginalDstPort)
}

// GetTranslatedFlow returns the post-NAT flow key
func (e *NATEntry) GetTranslatedFlow() types.FlowKey {
	return types.NewFlowKey(e.Protocol, e.TranslatedSrcIP, e.TranslatedSrcPort,
		e.TranslatedDstIP, e.TranslatedDstPort)
}

// String returns a human-readable representation of the NAT entry
func (e *NATEntry) String() string {
	return fmt.Sprintf("%s: %s:%d->%s:%d => %s:%d->%s:%d (%s)",
		e.TransformType,
		e.OriginalSrcIP, e.OriginalSrcPort,
		e.OriginalDstIP, e.OriginalDstPort,
		e.TranslatedSrcIP, e.TranslatedSrcPort,
		e.TranslatedDstIP, e.TranslatedDstPort,
		e.Protocol)
}

// NATChain represents a series of NAT transformations (for double NAT scenarios)
type NATChain struct {
	Transformations []NATEntry
	TotalLatency    time.Duration
	HopCount        int
}

// ConnectionState represents the state of a connection through NAT
type ConnectionState int

const (
	// StateNew indicates a new connection
	StateNew ConnectionState = iota
	// StateEstablished indicates an established connection
	StateEstablished
	// StateClosing indicates a connection in closing state
	StateClosing
	// StateClosed indicates a closed connection
	StateClosed
)

// FlowState tracks the state of a flow through NAT devices
type FlowState struct {
	FlowKey         types.FlowKey
	State           ConnectionState
	NATEntry        *NATEntry
	LastPacketTime  time.Time
	PacketsSent     int64
	PacketsReceived int64
	BytesSent       int64
	BytesReceived   int64
	TCPFlags        uint8 // Cumulative TCP flags seen
	IsSymmetric     bool  // True if both directions seen
}

// NATDetectionResult contains the results of NAT detection analysis
type NATDetectionResult struct {
	DetectedNATs     []NATEntry
	NATChains        []NATChain
	FlowStates       map[types.FlowKey]*FlowState
	DetectionMethod  string
	Confidence       float64
	AnalysisTime     time.Duration
	
	// Statistics
	TotalFlows       int
	NATtedFlows      int
	DoubleNATFlows   int
	SymmetricFlows   int
	
	// Detailed findings
	Findings []string
}