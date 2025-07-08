package live

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

)

func TestAlertManager(t *testing.T) {
	config := AlertManagerConfig{
		MaxAlerts:          1000,
		AlertRetention:     time.Hour,
		SuppressionWindow:  time.Minute * 5,
		NotificationWorkers: 2,
	}

	manager := NewAlertManager(config)
	if manager == nil {
		t.Fatal("Failed to create alert manager")
	}

	defer manager.Close()

	// Test basic configuration
	if manager.GetMaxAlerts() != config.MaxAlerts {
		t.Errorf("Expected max alerts %d, got %d", config.MaxAlerts, manager.GetMaxAlerts())
	}
}

func TestAlertManagerStartStop(t *testing.T) {
	config := AlertManagerConfig{
		MaxAlerts: 100,
		AlertRetention: time.Minute,
	}

	manager := NewAlertManager(config)
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// Test starting
	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start alert manager: %v", err)
	}

	if !manager.IsRunning() {
		t.Error("Expected alert manager to be running")
	}

	// Test stopping
	err = manager.Stop()
	if err != nil {
		t.Errorf("Failed to stop alert manager: %v", err)
	}

	if manager.IsRunning() {
		t.Error("Expected alert manager to be stopped")
	}
}

func TestAlertRule(t *testing.T) {
	tests := []struct {
		name      string
		rule      AlertRule
		event     AlertEvent
		shouldFire bool
	}{
		{
			name: "correlation rate threshold",
			rule: AlertRule{
				Name:        "low_correlation",
				Condition:   "correlation_rate < 0.8",
				Threshold:   0.8,
				Window:      time.Minute,
				Severity:    SeverityWarning,
			},
			event: AlertEvent{
				Type:  "correlation_rate",
				Value: 0.7,
				Metadata: map[string]interface{}{
					"window": "1m",
				},
			},
			shouldFire: true,
		},
		{
			name: "packet drop threshold",
			rule: AlertRule{
				Name:        "high_drops",
				Condition:   "packet_drops > 100",
				Threshold:   100,
				Window:      time.Minute,
				Severity:    SeverityCritical,
			},
			event: AlertEvent{
				Type:  "packet_drops",
				Value: 150,
			},
			shouldFire: true,
		},
		{
			name: "threshold not exceeded",
			rule: AlertRule{
				Name:        "low_latency",
				Condition:   "latency > 1000",
				Threshold:   1000,
				Window:      time.Minute,
				Severity:    SeverityInfo,
			},
			event: AlertEvent{
				Type:  "latency",
				Value: 500,
			},
			shouldFire: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rule.Evaluate(tt.event)
			if result != tt.shouldFire {
				t.Errorf("Expected rule to fire: %v, got: %v", tt.shouldFire, result)
			}
		})
	}
}

func TestAlertManagerRuleProcessing(t *testing.T) {
	config := AlertManagerConfig{
		MaxAlerts: 100,
		AlertRetention: time.Minute,
	}

	manager := NewAlertManager(config)
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start alert manager: %v", err)
	}
	defer manager.Stop()

	// Add alert rule
	rule := AlertRule{
		Name:        "test_rule",
		Condition:   "correlation_rate < 0.5",
		Threshold:   0.5,
		Window:      time.Second * 5,
		Severity:    SeverityWarning,
		Actions: []AlertAction{
			{Type: "log", Config: map[string]interface{}{"level": "warn"}},
		},
	}

	err = manager.AddRule(rule)
	if err != nil {
		t.Fatalf("Failed to add rule: %v", err)
	}

	// Create event that should trigger the rule
	event := AlertEvent{
		Type:      "correlation_rate",
		Value:     0.3,
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"capture_point": "point1",
		},
	}

	err = manager.ProcessEvent(event)
	if err != nil {
		t.Errorf("Failed to process event: %v", err)
	}

	// Give a small delay for async processing
	time.Sleep(time.Millisecond * 100)

	// Wait for alert to be generated
	timeout := time.After(time.Second * 2)
	alertReceived := false

	select {
	case alert := <-manager.Alerts():
		if alert.Rule != rule.Name {
			t.Errorf("Expected alert for rule %s, got %s", rule.Name, alert.Rule)
		}
		if alert.Severity != SeverityWarning {
			t.Errorf("Expected severity %v, got %v", SeverityWarning, alert.Severity)
		}
		alertReceived = true
		t.Logf("Received alert: %+v", alert)
	case <-timeout:
		// No alert received
	}

	if !alertReceived {
		t.Error("Expected alert to be generated")
	}
}

func TestAlertSuppression(t *testing.T) {
	config := AlertManagerConfig{
		MaxAlerts: 100,
		SuppressionWindow: time.Millisecond * 500,
	}

	manager := NewAlertManager(config)
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start alert manager: %v", err)
	}
	defer manager.Stop()

	// Add rule with suppression
	rule := AlertRule{
		Name:        "suppression_test",
		Condition:   "always_true",
		Threshold:   0,
		Window:      time.Second,
		Severity:    SeverityInfo,
		Suppression: time.Millisecond * 500,
	}

	err = manager.AddRule(rule)
	if err != nil {
		t.Fatalf("Failed to add rule: %v", err)
	}

	// Send multiple events quickly
	event := AlertEvent{
		Type:      "always_true",
		Value:     1,
		Timestamp: time.Now(),
	}

	alertCount := 0
	var mu sync.Mutex

	// Start collecting alerts
	go func() {
		timeout := time.After(time.Second * 2)
		for {
			select {
			case <-manager.Alerts():
				mu.Lock()
				alertCount++
				mu.Unlock()
			case <-timeout:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	// Send events rapidly
	for i := 0; i < 5; i++ {
		err = manager.ProcessEvent(event)
		if err != nil {
			t.Errorf("Failed to process event %d: %v", i, err)
		}
		time.Sleep(time.Millisecond * 50) // Faster than suppression window
	}

	// Wait for processing
	time.Sleep(time.Second)

	mu.Lock()
	finalAlertCount := alertCount
	mu.Unlock()

	// Should only get one alert due to suppression
	if finalAlertCount > 2 { // Allow some tolerance
		t.Errorf("Expected suppression to limit alerts, got %d", finalAlertCount)
	}

	t.Logf("Alert suppression test: %d alerts generated from 5 events", finalAlertCount)
}

func TestWebhookNotification(t *testing.T) {
	// Create test webhook server
	var receivedAlerts []Alert
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var alert Alert
		err := json.NewDecoder(r.Body).Decode(&alert)
		if err != nil {
			t.Errorf("Failed to decode webhook payload: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		mu.Lock()
		receivedAlerts = append(receivedAlerts, alert)
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := AlertManagerConfig{
		MaxAlerts: 100,
	}

	manager := NewAlertManager(config)
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start alert manager: %v", err)
	}
	defer manager.Stop()

	// Add rule with webhook action
	rule := AlertRule{
		Name:      "webhook_test",
		Condition: "test_event > 0",
		Threshold: 0,
		Window:    time.Second,
		Severity:  SeverityInfo,
		Actions: []AlertAction{
			{
				Type: "webhook",
				Config: map[string]interface{}{
					"url":     server.URL,
					"timeout": "5s",
				},
			},
		},
	}

	err = manager.AddRule(rule)
	if err != nil {
		t.Fatalf("Failed to add rule: %v", err)
	}

	// Trigger event
	event := AlertEvent{
		Type:      "test_event",
		Value:     1,
		Timestamp: time.Now(),
	}

	err = manager.ProcessEvent(event)
	if err != nil {
		t.Errorf("Failed to process event: %v", err)
	}

	// Wait for webhook delivery
	time.Sleep(time.Second)

	mu.Lock()
	webhookCount := len(receivedAlerts)
	mu.Unlock()

	if webhookCount != 1 {
		t.Errorf("Expected 1 webhook delivery, got %d", webhookCount)
	}

	if webhookCount > 0 {
		mu.Lock()
		alert := receivedAlerts[0]
		mu.Unlock()

		if alert.Rule != "webhook_test" {
			t.Errorf("Expected webhook for rule 'webhook_test', got '%s'", alert.Rule)
		}
	}
}

func TestAlertManagerMetrics(t *testing.T) {
	config := AlertManagerConfig{
		MaxAlerts: 100,
	}

	manager := NewAlertManager(config)
	defer manager.Close()

	// Test initial metrics
	metrics := manager.GetMetrics()
	if metrics.TotalAlerts != 0 {
		t.Errorf("Expected 0 total alerts initially, got %d", metrics.TotalAlerts)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start alert manager: %v", err)
	}
	defer manager.Stop()

	// Add rule and trigger alerts
	rule := AlertRule{
		Name:      "metrics_test",
		Condition: "test_metric > 5",
		Threshold: 5,
		Window:    time.Second,
		Severity:  SeverityInfo,
	}

	err = manager.AddRule(rule)
	if err != nil {
		t.Fatalf("Failed to add rule: %v", err)
	}

	// Generate events
	for i := 0; i < 3; i++ {
		event := AlertEvent{
			Type:  "test_metric",
			Value: 10, // Above threshold
			Timestamp: time.Now(),
		}

		err = manager.ProcessEvent(event)
		if err != nil {
			t.Errorf("Failed to process event %d: %v", i, err)
		}
		time.Sleep(time.Millisecond * 100)
	}

	// Wait for processing
	time.Sleep(time.Millisecond * 500)

	// Check metrics
	metrics = manager.GetMetrics()
	if metrics.TotalAlerts == 0 {
		t.Error("Expected some alerts to be generated")
	}

	if metrics.EventsProcessed < 3 {
		t.Errorf("Expected at least 3 events processed, got %d", metrics.EventsProcessed)
	}

	t.Logf("Alert manager metrics: %+v", metrics)
}

func TestAlertRetention(t *testing.T) {
	config := AlertManagerConfig{
		MaxAlerts: 100,
		AlertRetention: time.Millisecond * 500, // Short retention for testing
	}

	manager := NewAlertManager(config)
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start alert manager: %v", err)
	}
	defer manager.Stop()

	rule := AlertRule{
		Name:      "retention_test",
		Condition: "test_value > 0",
		Threshold: 0,
		Window:    time.Second,
		Severity:  SeverityInfo,
	}

	err = manager.AddRule(rule)
	if err != nil {
		t.Fatalf("Failed to add rule: %v", err)
	}

	// Generate alert
	event := AlertEvent{
		Type:      "test_value",
		Value:     1,
		Timestamp: time.Now(),
	}

	err = manager.ProcessEvent(event)
	if err != nil {
		t.Errorf("Failed to process event: %v", err)
	}

	// Wait for alert to be generated
	time.Sleep(time.Millisecond * 100)

	// Check that alert exists
	alerts := manager.GetRecentAlerts(time.Minute)
	if len(alerts) == 0 {
		t.Error("Expected alert to exist")
	}

	// Wait for retention period to expire
	time.Sleep(time.Millisecond * 600)

	// Check that alert was cleaned up
	alerts = manager.GetRecentAlerts(time.Minute)
	if len(alerts) > 0 {
		t.Error("Expected alert to be cleaned up after retention period")
	}

	t.Log("Alert retention test completed successfully")
}

func TestComplexAlertConditions(t *testing.T) {
	config := AlertManagerConfig{
		MaxAlerts: 100,
	}

	manager := NewAlertManager(config)
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start alert manager: %v", err)
	}
	defer manager.Stop()

	// Complex rule with multiple conditions
	rule := AlertRule{
		Name:      "complex_condition",
		Condition: "correlation_rate < 0.8 AND packet_drops > 10",
		Threshold: 0.8,
		Window:    time.Second * 2,
		Severity:  SeverityWarning,
	}

	err = manager.AddRule(rule)
	if err != nil {
		t.Fatalf("Failed to add rule: %v", err)
	}

	alertCount := 0
	var mu sync.Mutex

	// Start collecting alerts
	go func() {
		timeout := time.After(time.Second * 3)
		for {
			select {
			case <-manager.Alerts():
				mu.Lock()
				alertCount++
				mu.Unlock()
			case <-timeout:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	// Send events that should trigger the complex condition
	events := []AlertEvent{
		{Type: "correlation_rate", Value: 0.7, Timestamp: time.Now()}, // First condition met
		{Type: "packet_drops", Value: 15, Timestamp: time.Now().Add(time.Millisecond * 100)}, // Second condition met
	}

	for _, event := range events {
		err = manager.ProcessEvent(event)
		if err != nil {
			t.Errorf("Failed to process event: %v", err)
		}
	}

	// Wait for processing
	time.Sleep(time.Second)

	mu.Lock()
	finalAlertCount := alertCount
	mu.Unlock()

	if finalAlertCount == 0 {
		t.Error("Expected complex condition to trigger alert")
	}

	t.Logf("Complex condition test: %d alerts generated", finalAlertCount)
}