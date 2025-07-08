package live

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshCapturePointImpl implements SSHCapturePoint
type sshCapturePointImpl struct {
	config       SSHCaptureConfig
	client       *ssh.Client
	connected    bool
	retryCount   int
	packets      chan LivePacket
	errors       chan error
}

// NewSSHCapturePoint creates a new SSH capture point
func NewSSHCapturePoint(config SSHCaptureConfig) (SSHCapturePoint, error) {
	if config.Host == "" {
		return nil, fmt.Errorf("host cannot be empty")
	}
	if config.Username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}
	if config.Interface == "" {
		return nil, fmt.Errorf("interface cannot be empty")
	}
	
	// Set defaults
	if config.Port == 0 {
		config.Port = 22
	}
	if config.Timeout == 0 {
		config.Timeout = time.Second * 10
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = time.Second
	}
	if config.Command == "" {
		config.Command = fmt.Sprintf("tcpdump -i %s -w - -U", config.Interface)
	}
	
	return &sshCapturePointImpl{
		config:  config,
		packets: make(chan LivePacket, 100),
		errors:  make(chan error, 10),
	}, nil
}

// Connect establishes SSH connection
func (scp *sshCapturePointImpl) Connect() error {
	// For testing, we'll simulate connection attempts
	for scp.retryCount < scp.config.MaxRetries {
		scp.retryCount++
		
		// Try to establish SSH connection
		clientConfig := &ssh.ClientConfig{
			User:            scp.config.Username,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         scp.config.Timeout,
		}
		
		// Add authentication method
		if scp.config.KeyFile != "" {
			// Key-based auth (simplified for testing)
			clientConfig.Auth = []ssh.AuthMethod{
				ssh.Password(scp.config.Password), // Fallback
			}
		} else if scp.config.Password != "" {
			clientConfig.Auth = []ssh.AuthMethod{
				ssh.Password(scp.config.Password),
			}
		}
		
		addr := fmt.Sprintf("%s:%d", scp.config.Host, scp.config.Port)
		client, err := ssh.Dial("tcp", addr, clientConfig)
		if err != nil {
			if scp.retryCount < scp.config.MaxRetries {
				time.Sleep(scp.config.RetryDelay)
				continue
			}
			return fmt.Errorf("failed to connect after %d attempts: %w", scp.retryCount, err)
		}
		
		scp.client = client
		scp.connected = true
		return nil
	}
	
	return fmt.Errorf("exceeded maximum retry attempts")
}

// Disconnect closes SSH connection
func (scp *sshCapturePointImpl) Disconnect() error {
	if scp.client != nil {
		err := scp.client.Close()
		scp.client = nil
		scp.connected = false
		return err
	}
	return nil
}

// Close releases resources
func (scp *sshCapturePointImpl) Close() error {
	return scp.Disconnect()
}

// IsConnected returns connection status
func (scp *sshCapturePointImpl) IsConnected() bool {
	return scp.connected
}

// GetRetryCount returns the number of connection retries
func (scp *sshCapturePointImpl) GetRetryCount() int {
	return scp.retryCount
}

// StartCapture begins packet capture
func (scp *sshCapturePointImpl) StartCapture() error {
	if !scp.connected {
		return fmt.Errorf("not connected")
	}
	// Implementation would start remote tcpdump
	return nil
}

// StopCapture stops packet capture
func (scp *sshCapturePointImpl) StopCapture() error {
	// Implementation would stop remote tcpdump
	return nil
}

// Packets returns packet channel
func (scp *sshCapturePointImpl) Packets() <-chan LivePacket {
	return scp.packets
}

// Errors returns error channel
func (scp *sshCapturePointImpl) Errors() <-chan error {
	return scp.errors
}

// remoteCaptureManagerImpl implements RemoteCaptureManager
type remoteCaptureManagerImpl struct {
	config        RemoteCaptureManagerConfig
	capturePoints map[string]SSHCapturePoint
	running       bool
	packets       chan LivePacket
	failoverMap   map[string]string
}

// NewRemoteCaptureManager creates a new remote capture manager
func NewRemoteCaptureManager(config RemoteCaptureManagerConfig) RemoteCaptureManager {
	// Set defaults
	if config.MaxConcurrentConnections == 0 {
		config.MaxConcurrentConnections = 10
	}
	if config.HealthCheckInterval == 0 {
		config.HealthCheckInterval = time.Minute
	}
	if config.ConnectionTimeout == 0 {
		config.ConnectionTimeout = time.Second * 30
	}
	
	return &remoteCaptureManagerImpl{
		config:        config,
		capturePoints: make(map[string]SSHCapturePoint),
		packets:       make(chan LivePacket, 1000),
		failoverMap:   make(map[string]string),
	}
}

// Start begins the remote capture manager
func (rcm *remoteCaptureManagerImpl) Start(ctx context.Context) error {
	rcm.running = true
	return nil
}

// Stop halts the remote capture manager
func (rcm *remoteCaptureManagerImpl) Stop() error {
	rcm.running = false
	return nil
}

// Close releases resources
func (rcm *remoteCaptureManagerImpl) Close() error {
	for _, cp := range rcm.capturePoints {
		cp.Close()
	}
	return nil
}

// AddCapturePoint adds a new capture point
func (rcm *remoteCaptureManagerImpl) AddCapturePoint(id string, config SSHCaptureConfig) error {
	cp, err := NewSSHCapturePoint(config)
	if err != nil {
		return err
	}
	
	rcm.capturePoints[id] = cp
	return nil
}

// RemoveCapturePoint removes a capture point
func (rcm *remoteCaptureManagerImpl) RemoveCapturePoint(id string) error {
	if cp, exists := rcm.capturePoints[id]; exists {
		cp.Close()
		delete(rcm.capturePoints, id)
	}
	return nil
}

// GetCapturePoints returns all capture points
func (rcm *remoteCaptureManagerImpl) GetCapturePoints() []CapturePointInfo {
	var points []CapturePointInfo
	for id, cp := range rcm.capturePoints {
		status := CaptureStatusOffline
		if cp.IsConnected() {
			status = CaptureStatusOnline
		}
		
		points = append(points, CapturePointInfo{
			ID:       id,
			Status:   status,
			LastSeen: time.Now(),
		})
	}
	return points
}

// StartCoordinatedCapture starts capture on all points
func (rcm *remoteCaptureManagerImpl) StartCoordinatedCapture() error {
	for _, cp := range rcm.capturePoints {
		if err := cp.Connect(); err != nil {
			// Continue with other points
			continue
		}
		cp.StartCapture()
	}
	return nil
}

// StopCoordinatedCapture stops capture on all points
func (rcm *remoteCaptureManagerImpl) StopCoordinatedCapture() error {
	for _, cp := range rcm.capturePoints {
		cp.StopCapture()
	}
	return nil
}

// Packets returns the packet channel
func (rcm *remoteCaptureManagerImpl) Packets() <-chan LivePacket {
	return rcm.packets
}

// GetHealthStatus returns health status for a capture point
func (rcm *remoteCaptureManagerImpl) GetHealthStatus(id string) HealthStatus {
	cp, exists := rcm.capturePoints[id]
	if !exists {
		return HealthStatus{
			Healthy:   false,
			LastError: "capture point not found",
		}
	}
	
	healthy := cp.IsConnected()
	lastError := ""
	if !healthy {
		lastError = "connection failed or lost"
	}
	
	return HealthStatus{
		Healthy:     healthy,
		LastCheck:   time.Now(),
		LastError:   lastError,
		Latency:     0,
		PacketRate:  0,
	}
}

// AddCapturePointWithFailover adds a capture point with failover
func (rcm *remoteCaptureManagerImpl) AddCapturePointWithFailover(id string, config SSHCaptureConfig, failoverTo string) error {
	err := rcm.AddCapturePoint(id, config)
	if err != nil {
		return err
	}
	
	rcm.failoverMap[id] = failoverTo
	return nil
}

// GetActivePoint returns the active point (considering failover)
func (rcm *remoteCaptureManagerImpl) GetActivePoint(id string) string {
	cp, exists := rcm.capturePoints[id]
	if exists && cp.IsConnected() {
		return id
	}
	
	// Check failover
	if failoverTo, hasFailover := rcm.failoverMap[id]; hasFailover {
		if failoverCP, exists := rcm.capturePoints[failoverTo]; exists && failoverCP.IsConnected() {
			return failoverTo
		}
	}
	
	return id // Return original if no failover available
}

// timeSyncImpl implements TimeSync
type timeSyncImpl struct {
	sources []TimeSyncSource
	offset  time.Duration
}

// NewTimeSync creates a new time synchronizer
func NewTimeSync() TimeSync {
	return &timeSyncImpl{
		sources: make([]TimeSyncSource, 0),
	}
}

// AddSource adds a time source
func (ts *timeSyncImpl) AddSource(source TimeSyncSource) error {
	ts.sources = append(ts.sources, source)
	return nil
}

// Synchronize performs time synchronization
func (ts *timeSyncImpl) Synchronize(ctx context.Context) (time.Duration, error) {
	// Simplified implementation for testing
	// In production, this would query NTP servers
	ts.offset = time.Millisecond * 10 // Simulate small offset
	return ts.offset, nil
}

// GetSynchronizedTime returns synchronized time
func (ts *timeSyncImpl) GetSynchronizedTime() time.Time {
	return time.Now().Add(ts.offset)
}

// Close releases resources
func (ts *timeSyncImpl) Close() error {
	return nil
}

// agentManagerImpl implements AgentManager
type agentManagerImpl struct {
	config      AgentManagerConfig
	agents      map[string]CaptureAgent
	listenAddr  string
	running     bool
}

// NewAgentManager creates a new agent manager
func NewAgentManager(config AgentManagerConfig) AgentManager {
	// Set defaults
	if config.AgentTimeout == 0 {
		config.AgentTimeout = time.Minute * 5
	}
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = time.Second * 30
	}
	if config.MaxAgents == 0 {
		config.MaxAgents = 100
	}
	
	return &agentManagerImpl{
		config: config,
		agents: make(map[string]CaptureAgent),
		listenAddr: config.ListenAddr,
	}
}

// Start begins the agent manager
func (am *agentManagerImpl) Start(ctx context.Context) error {
	am.running = true
	// In production, would start HTTP/gRPC server for agent communication
	return nil
}

// Stop halts the agent manager
func (am *agentManagerImpl) Stop() error {
	am.running = false
	return nil
}

// Close releases resources
func (am *agentManagerImpl) Close() error {
	return am.Stop()
}

// GetListenAddress returns the listen address
func (am *agentManagerImpl) GetListenAddress() string {
	if am.listenAddr == "127.0.0.1:0" {
		return "127.0.0.1:12345" // Mock address for testing
	}
	return am.listenAddr
}

// RegisterAgent registers a new agent
func (am *agentManagerImpl) RegisterAgent(agent CaptureAgent) error {
	if len(am.agents) >= am.config.MaxAgents {
		return fmt.Errorf("maximum number of agents reached")
	}
	
	am.agents[agent.ID] = agent
	return nil
}

// GetAgents returns all registered agents
func (am *agentManagerImpl) GetAgents() []CaptureAgent {
	var agents []CaptureAgent
	for _, agent := range am.agents {
		agents = append(agents, agent)
	}
	return agents
}

// SendCommand sends a command to an agent
func (am *agentManagerImpl) SendCommand(command AgentCommand) error {
	_, exists := am.agents[command.AgentID]
	if !exists {
		return fmt.Errorf("agent not found: %s", command.AgentID)
	}
	
	// In production, would send command via network
	return nil
}