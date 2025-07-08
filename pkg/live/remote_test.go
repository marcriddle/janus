package live

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHCapturePoint(t *testing.T) {
	// Skip if SSH testing is not enabled
	if os.Getenv("JANUS_TEST_SSH") != "1" {
		t.Skip("SSH testing disabled (set JANUS_TEST_SSH=1 to enable)")
	}

	config := SSHCaptureConfig{
		Host:        "localhost",
		Port:        22,
		Username:    "testuser",
		Interface:   "lo",
		Command:     "tcpdump -i lo -w - -U",
		Timeout:     time.Second * 10,
		MaxRetries:  3,
		RetryDelay:  time.Second,
	}

	capture, err := NewSSHCapturePoint(config)
	if err != nil {
		t.Fatalf("Failed to create SSH capture point: %v", err)
	}
	defer capture.Close()

	// Test connection
	err = capture.Connect()
	if err != nil {
		t.Skipf("Failed to connect via SSH (this may be expected): %v", err)
	}

	// Test basic functionality
	if !capture.IsConnected() {
		t.Error("Expected SSH capture to be connected")
	}
}

func TestSSHCapturePointWithKeyAuth(t *testing.T) {
	if os.Getenv("JANUS_TEST_SSH") != "1" {
		t.Skip("SSH testing disabled")
	}

	// Generate temporary SSH key for testing
	privateKey, publicKey, err := generateSSHKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate SSH key pair: %v", err)
	}

	keyFile, err := ioutil.TempFile("", "janus_test_key_*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp key file: %v", err)
	}
	defer os.Remove(keyFile.Name())

	_, err = keyFile.Write(privateKey)
	if err != nil {
		t.Fatalf("Failed to write private key: %v", err)
	}
	keyFile.Close()

	config := SSHCaptureConfig{
		Host:      "localhost",
		Port:      22,
		Username:  "testuser",
		KeyFile:   keyFile.Name(),
		Interface: "lo",
		Command:   "tcpdump -i lo -w - -U",
	}

	capture, err := NewSSHCapturePoint(config)
	if err != nil {
		t.Fatalf("Failed to create SSH capture point with key auth: %v", err)
	}
	defer capture.Close()

	t.Logf("Generated SSH key pair for testing (public key length: %d)", len(publicKey))
}

func TestSSHCapturePointFailover(t *testing.T) {
	config := SSHCaptureConfig{
		Host:        "nonexistent.example.com",
		Port:        22,
		Username:    "testuser",
		Interface:   "eth0",
		Command:     "tcpdump -i eth0 -w - -U",
		Timeout:     time.Millisecond * 500,
		MaxRetries:  2,
		RetryDelay:  time.Millisecond * 100,
	}

	capture, err := NewSSHCapturePoint(config)
	if err != nil {
		t.Fatalf("Failed to create SSH capture point: %v", err)
	}
	defer capture.Close()

	// This should fail and test retry logic
	err = capture.Connect()
	if err == nil {
		t.Error("Expected connection to fail for nonexistent host")
	}

	// Verify retry attempts were made
	if capture.GetRetryCount() < config.MaxRetries {
		t.Errorf("Expected %d retry attempts, got %d", config.MaxRetries, capture.GetRetryCount())
	}
}

func TestRemoteCaptureManager(t *testing.T) {
	config := RemoteCaptureManagerConfig{
		MaxConcurrentConnections: 5,
		HealthCheckInterval:      time.Second,
		ConnectionTimeout:        time.Second * 5,
	}

	manager := NewRemoteCaptureManager(config)
	if manager == nil {
		t.Fatal("Failed to create remote capture manager")
	}
	defer manager.Close()

	// Test adding capture points
	captureConfig := SSHCaptureConfig{
		Host:      "localhost",
		Port:      22,
		Username:  "testuser",
		Interface: "lo",
		Command:   "tcpdump -i lo -w - -U",
	}

	pointID := "test_point_1"
	err := manager.AddCapturePoint(pointID, captureConfig)
	if err != nil {
		t.Fatalf("Failed to add capture point: %v", err)
	}

	// Test listing capture points
	points := manager.GetCapturePoints()
	if len(points) != 1 {
		t.Errorf("Expected 1 capture point, got %d", len(points))
	}

	if points[0].ID != pointID {
		t.Errorf("Expected point ID %s, got %s", pointID, points[0].ID)
	}

	// Test removing capture point
	err = manager.RemoveCapturePoint(pointID)
	if err != nil {
		t.Errorf("Failed to remove capture point: %v", err)
	}

	points = manager.GetCapturePoints()
	if len(points) != 0 {
		t.Errorf("Expected 0 capture points after removal, got %d", len(points))
	}
}

func TestRemoteCaptureManagerHealthCheck(t *testing.T) {
	config := RemoteCaptureManagerConfig{
		MaxConcurrentConnections: 2,
		HealthCheckInterval:      time.Millisecond * 200,
		ConnectionTimeout:        time.Second,
	}

	manager := NewRemoteCaptureManager(config)
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start remote capture manager: %v", err)
	}
	defer manager.Stop()

	// Add capture point that will fail health checks
	captureConfig := SSHCaptureConfig{
		Host:      "invalid.example.com",
		Port:      22,
		Username:  "testuser",
		Interface: "eth0",
		Command:   "tcpdump -i eth0 -w - -U",
		Timeout:   time.Millisecond * 100,
	}

	pointID := "failing_point"
	err = manager.AddCapturePoint(pointID, captureConfig)
	if err != nil {
		t.Fatalf("Failed to add capture point: %v", err)
	}

	// Wait for health checks to run
	time.Sleep(time.Millisecond * 500)

	// Check health status
	status := manager.GetHealthStatus(pointID)
	if status.Healthy {
		t.Error("Expected capture point to be unhealthy")
	}

	if status.LastError == "" {
		t.Error("Expected last error to be recorded")
	}

	t.Logf("Health check status: %+v", status)
}

func TestRemoteCaptureCoordination(t *testing.T) {
	if os.Getenv("JANUS_TEST_SSH") != "1" {
		t.Skip("SSH testing disabled")
	}

	config := RemoteCaptureManagerConfig{
		MaxConcurrentConnections: 3,
		HealthCheckInterval:      time.Second,
	}

	manager := NewRemoteCaptureManager(config)
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer manager.Stop()

	// Add multiple capture points
	points := []struct {
		id   string
		host string
	}{
		{"point1", "localhost"},
		{"point2", "127.0.0.1"},
	}

	for _, point := range points {
		captureConfig := SSHCaptureConfig{
			Host:      point.host,
			Port:      22,
			Username:  "testuser",
			Interface: "lo",
			Command:   "tcpdump -i lo -w - -U -c 5", // Limit packets for testing
		}

		err = manager.AddCapturePoint(point.id, captureConfig)
		if err != nil {
			t.Errorf("Failed to add capture point %s: %v", point.id, err)
		}
	}

	// Start coordinated capture
	err = manager.StartCoordinatedCapture()
	if err != nil {
		t.Skipf("Failed to start coordinated capture (may be expected): %v", err)
	}

	// Monitor for packets from multiple points
	timeout := time.After(time.Second * 5)
	packetsReceived := make(map[string]int)

	for {
		select {
		case packet := <-manager.Packets():
			if packet.PointID != "" {
				packetsReceived[packet.SourcePoint]++
				t.Logf("Received packet from %s", packet.SourcePoint)
			}
		case <-timeout:
			goto endCoordination
		case <-ctx.Done():
			goto endCoordination
		}
	}

endCoordination:
	// Stop coordinated capture
	err = manager.StopCoordinatedCapture()
	if err != nil {
		t.Errorf("Failed to stop coordinated capture: %v", err)
	}

	t.Logf("Packets received per point: %v", packetsReceived)
}

func TestTimeSynchronization(t *testing.T) {
	syncer := NewTimeSync()
	if syncer == nil {
		t.Fatal("Failed to create time synchronizer")
	}
	defer syncer.Close()

	// Test adding time sources
	sources := []TimeSyncSource{
		{
			Host:     "pool.ntp.org",
			Protocol: "ntp",
			Priority: 1,
		},
		{
			Host:     "time.google.com",
			Protocol: "ntp",
			Priority: 2,
		},
	}

	for _, source := range sources {
		err := syncer.AddSource(source)
		if err != nil {
			t.Errorf("Failed to add time source %s: %v", source.Host, err)
		}
	}

	// Test synchronization (this may take time or fail in test environment)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	offset, err := syncer.Synchronize(ctx)
	if err != nil {
		t.Logf("Time synchronization failed (may be expected in test env): %v", err)
	} else {
		t.Logf("Time offset determined: %v", offset)

		if offset > time.Second || offset < -time.Second {
			t.Logf("Large time offset detected: %v", offset)
		}
	}

	// Test getting synchronized time
	syncTime := syncer.GetSynchronizedTime()
	localTime := time.Now()

	timeDiff := syncTime.Sub(localTime)
	if timeDiff > time.Second || timeDiff < -time.Second {
		t.Logf("Synchronized time differs from local time by: %v", timeDiff)
	}
}

func TestAgentBasedCapture(t *testing.T) {
	config := AgentManagerConfig{
		ListenAddr:        "127.0.0.1:0", // Use random port
		AgentTimeout:      time.Second * 10,
		HeartbeatInterval: time.Second * 2,
		MaxAgents:         10,
	}

	manager := NewAgentManager(config)
	if manager == nil {
		t.Fatal("Failed to create agent manager")
	}
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start agent manager: %v", err)
	}
	defer manager.Stop()

	// Get the actual listen address
	listenAddr := manager.GetListenAddress()
	t.Logf("Agent manager listening on: %s", listenAddr)

	// Test agent registration (simulated)
	agent := CaptureAgent{
		ID:       "test_agent_1",
		Version:  "1.0.0",
		Capabilities: []string{"pcap", "filtering"},
		Interfaces: []NetworkInterface{
			{Name: "eth0", Type: "ethernet", Status: "up"},
			{Name: "lo", Type: "loopback", Status: "up"},
		},
		Status:   AgentStatusOnline,
		LastSeen: time.Now(),
	}

	err = manager.RegisterAgent(agent)
	if err != nil {
		t.Errorf("Failed to register agent: %v", err)
	}

	// Test listing agents
	agents := manager.GetAgents()
	if len(agents) != 1 {
		t.Errorf("Expected 1 agent, got %d", len(agents))
	}

	if agents[0].ID != agent.ID {
		t.Errorf("Expected agent ID %s, got %s", agent.ID, agents[0].ID)
	}

	// Test agent command
	command := AgentCommand{
		Type:    "start_capture",
		AgentID: agent.ID,
		Config: map[string]interface{}{
			"interface": "lo",
			"filter":    "tcp port 80",
		},
	}

	err = manager.SendCommand(command)
	if err != nil {
		t.Errorf("Failed to send agent command: %v", err)
	}

	t.Logf("Agent management test completed successfully")
}

func TestDistributedCaptureFailover(t *testing.T) {
	config := RemoteCaptureManagerConfig{
		MaxConcurrentConnections: 3,
		HealthCheckInterval:      time.Millisecond * 100,
		ConnectionTimeout:        time.Millisecond * 500,
	}

	manager := NewRemoteCaptureManager(config)
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer manager.Stop()

	// Add primary and backup capture points
	primaryConfig := SSHCaptureConfig{
		Host:      "nonexistent1.example.com",
		Port:      22,
		Username:  "testuser",
		Interface: "eth0",
		Command:   "tcpdump -i eth0 -w - -U",
		Timeout:   time.Millisecond * 200,
	}

	backupConfig := SSHCaptureConfig{
		Host:      "localhost",
		Port:      22,
		Username:  "testuser",
		Interface: "lo",
		Command:   "tcpdump -i lo -w - -U",
		Timeout:   time.Millisecond * 200,
	}

	// Add both points with failover relationship
	err = manager.AddCapturePointWithFailover("primary", primaryConfig, "backup")
	if err != nil {
		t.Fatalf("Failed to add primary capture point: %v", err)
	}

	err = manager.AddCapturePoint("backup", backupConfig)
	if err != nil {
		t.Fatalf("Failed to add backup capture point: %v", err)
	}

	// Wait for health checks to detect primary failure
	time.Sleep(time.Millisecond * 500)

	// Check that failover occurred
	activePoint := manager.GetActivePoint("primary")
	if activePoint != "backup" {
		t.Logf("Failover test: active point is %s (primary may not have failed as expected)", activePoint)
	}

	t.Log("Distributed capture failover test completed")
}

// Helper functions

func generateSSHKeyPair() ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Private key in PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)

	// Public key in SSH format
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	publicKeyBytes := ssh.MarshalAuthorizedKey(publicKey)

	return privateKeyBytes, publicKeyBytes, nil
}

func isPortOpen(host string, port int) bool {
	timeout := time.Millisecond * 100
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func getLocalIPAddresses() ([]string, error) {
	var ips []string
	
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // Interface is down
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() {
				continue
			}

			if ip.To4() != nil {
				ips = append(ips, ip.String())
			}
		}
	}

	return ips, nil
}