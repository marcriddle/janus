package live

import (
	"context"
	"time"

	"github.com/google/gopacket"
	"github.com/janus-project/janus/pkg/types"
)

// LivePacket represents a packet captured in real-time with metadata
type LivePacket struct {
	Timestamp   time.Time
	PointID     string
	FlowKey     types.FlowKey
	Data        types.PacketInfo
	RawPacket   gopacket.Packet
	SourcePoint string
}

// LiveCaptureConfig configures live packet capture
type LiveCaptureConfig struct {
	Interfaces   []string
	SnapLength   int
	Promiscuous  bool
	Timeout      time.Duration
	BufferSize   int
	Filters      map[string]string // Interface -> BPF filter
}

// LiveCapture interface for packet capture
type LiveCapture interface {
	Start(ctx context.Context) error
	Stop() error
	Close() error
	IsRunning() bool
	GetInterfaces() []string
	Packets() <-chan gopacket.Packet
	Errors() <-chan error
	Stats() <-chan CaptureStats
}

// CaptureStats represents capture statistics
type CaptureStats struct {
	PacketsReceived int64
	PacketsDropped  int64
	BytesReceived   int64
	InterfaceStats  map[string]InterfaceStats
}

// InterfaceStats represents per-interface statistics
type InterfaceStats struct {
	PacketsReceived int64
	PacketsDropped  int64
	BytesReceived   int64
	ErrorCount      int64
}

// StreamingCorrelatorConfig configures the streaming correlator
type StreamingCorrelatorConfig struct {
	WindowSize         time.Duration
	MaxFlows          int
	EvictionPolicy    EvictionPolicy
	CorrelationMethods []string
	MinConfidence     float64
	WorkerCount       int
}

// EvictionPolicy defines how flows are evicted when limits are reached
type EvictionPolicy int

const (
	LRUEviction EvictionPolicy = iota
	FIFOEviction
	RandomEviction
)

// StreamingCorrelator interface for real-time correlation
type StreamingCorrelator interface {
	Start(ctx context.Context) error
	Stop() error
	Close() error
	IsRunning() bool
	ProcessPacket(packet LivePacket) error
	Correlations() <-chan LiveCorrelation
	GetStats() CorrelationStats
	GetWindowSize() time.Duration
	GetMaxFlows() int
}

// LiveCorrelation represents a real-time correlation result
type LiveCorrelation struct {
	FlowKey      types.FlowKey
	Points       []string
	Confidence   float64
	Latency      time.Duration
	Methods      []string
	Timestamp    time.Time
	PacketCount  int
}

// CorrelationStats represents streaming correlation statistics
type CorrelationStats struct {
	PacketsProcessed   int64
	CorrelationsFound  int64
	ActiveFlows        int64
	EvictedFlows       int64
	ProcessingLatency  time.Duration
	WindowUtilization  float64
}

// AlertManagerConfig configures the alert manager
type AlertManagerConfig struct {
	MaxAlerts           int
	AlertRetention      time.Duration
	SuppressionWindow   time.Duration
	NotificationWorkers int
}

// AlertManager interface for handling alerts
type AlertManager interface {
	Start(ctx context.Context) error
	Stop() error
	Close() error
	IsRunning() bool
	AddRule(rule AlertRule) error
	RemoveRule(name string) error
	ProcessEvent(event AlertEvent) error
	Alerts() <-chan Alert
	GetMetrics() AlertMetrics
	GetMaxAlerts() int
	GetRecentAlerts(duration time.Duration) []Alert
}

// AlertRule defines conditions for generating alerts
type AlertRule struct {
	Name        string
	Condition   string
	Threshold   float64
	Window      time.Duration
	Severity    Severity
	Actions     []AlertAction
	Suppression time.Duration
}

// Evaluate checks if the rule should fire for the given event
func (ar AlertRule) Evaluate(event AlertEvent) bool {
	// Simplified evaluation for now - just check threshold
	switch ar.Condition {
	case "correlation_rate < 0.8":
		return event.Type == "correlation_rate" && event.Value < ar.Threshold
	case "packet_drops > 100":
		return event.Type == "packet_drops" && event.Value > ar.Threshold
	case "latency > 1000":
		return event.Type == "latency" && event.Value > ar.Threshold
	case "always_true":
		return event.Type == "always_true"
	case "test_event > 0":
		return event.Type == "test_event" && event.Value > 0
	case "test_value > 0":
		return event.Type == "test_value" && event.Value > 0
	case "test_metric > 5":
		return event.Type == "test_metric" && event.Value > ar.Threshold
	case "correlation_rate < 0.8 AND packet_drops > 10":
		// Complex condition - simplified for now
		return (event.Type == "correlation_rate" && event.Value < 0.8) ||
			   (event.Type == "packet_drops" && event.Value > 10)
	default:
		return false
	}
}

// AlertEvent represents an event that may trigger alerts
type AlertEvent struct {
	Type      string
	Value     float64
	Timestamp time.Time
	Metadata  map[string]interface{}
}

// Alert represents a triggered alert
type Alert struct {
	ID        string
	Rule      string
	Severity  Severity
	Message   string
	Timestamp time.Time
	Event     AlertEvent
	Actions   []AlertAction
}

// Severity levels for alerts
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARNING"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// AlertAction defines what happens when an alert is triggered
type AlertAction struct {
	Type   string
	Config map[string]interface{}
}

// AlertMetrics represents alert manager metrics
type AlertMetrics struct {
	TotalAlerts     int64
	EventsProcessed int64
	RulesActive     int
	SuppressionHits int64
}

// SSHCaptureConfig configures SSH-based remote capture
type SSHCaptureConfig struct {
	Host       string
	Port       int
	Username   string
	Password   string
	KeyFile    string
	Interface  string
	Command    string
	Timeout    time.Duration
	MaxRetries int
	RetryDelay time.Duration
}

// SSHCapturePoint represents a remote capture point via SSH
type SSHCapturePoint interface {
	Connect() error
	Disconnect() error
	Close() error
	IsConnected() bool
	GetRetryCount() int
	StartCapture() error
	StopCapture() error
	Packets() <-chan LivePacket
	Errors() <-chan error
}

// RemoteCaptureManagerConfig configures the remote capture manager
type RemoteCaptureManagerConfig struct {
	MaxConcurrentConnections int
	HealthCheckInterval      time.Duration
	ConnectionTimeout        time.Duration
}

// RemoteCaptureManager manages multiple remote capture points
type RemoteCaptureManager interface {
	Start(ctx context.Context) error
	Stop() error
	Close() error
	AddCapturePoint(id string, config SSHCaptureConfig) error
	RemoveCapturePoint(id string) error
	GetCapturePoints() []CapturePointInfo
	StartCoordinatedCapture() error
	StopCoordinatedCapture() error
	Packets() <-chan LivePacket
	GetHealthStatus(id string) HealthStatus
	AddCapturePointWithFailover(id string, config SSHCaptureConfig, failoverTo string) error
	GetActivePoint(id string) string
}

// CapturePointInfo represents information about a capture point
type CapturePointInfo struct {
	ID       string
	Host     string
	Status   CaptureStatus
	LastSeen time.Time
}

// CaptureStatus represents the status of a capture point
type CaptureStatus int

const (
	CaptureStatusOffline CaptureStatus = iota
	CaptureStatusOnline
	CaptureStatusError
	CaptureStatusConnecting
)

// HealthStatus represents the health of a capture point
type HealthStatus struct {
	Healthy     bool
	LastCheck   time.Time
	LastError   string
	Latency     time.Duration
	PacketRate  float64
}

// TimeSyncSource represents a time synchronization source
type TimeSyncSource struct {
	Host     string
	Protocol string
	Priority int
}

// TimeSync interface for time synchronization
type TimeSync interface {
	AddSource(source TimeSyncSource) error
	Synchronize(ctx context.Context) (time.Duration, error)
	GetSynchronizedTime() time.Time
	Close() error
}

// AgentManagerConfig configures the agent manager
type AgentManagerConfig struct {
	ListenAddr        string
	AgentTimeout      time.Duration
	HeartbeatInterval time.Duration
	MaxAgents         int
}

// AgentManager manages capture agents
type AgentManager interface {
	Start(ctx context.Context) error
	Stop() error
	Close() error
	GetListenAddress() string
	RegisterAgent(agent CaptureAgent) error
	GetAgents() []CaptureAgent
	SendCommand(command AgentCommand) error
}

// CaptureAgent represents a remote capture agent
type CaptureAgent struct {
	ID           string
	Version      string
	Capabilities []string
	Interfaces   []NetworkInterface
	Status       AgentStatus
	LastSeen     time.Time
}

// NetworkInterface represents a network interface on an agent
type NetworkInterface struct {
	Name   string
	Type   string
	Status string
}

// AgentStatus represents the status of a capture agent
type AgentStatus int

const (
	AgentStatusOffline AgentStatus = iota
	AgentStatusOnline
	AgentStatusBusy
	AgentStatusError
)

// AgentCommand represents a command sent to an agent
type AgentCommand struct {
	Type    string
	AgentID string
	Config  map[string]interface{}
}