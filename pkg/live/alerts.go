package live

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// alertManagerImpl implements the AlertManager interface
type alertManagerImpl struct {
	config   AlertManagerConfig
	running  bool
	mu       sync.RWMutex
	
	// Rules and alerts
	rules    map[string]AlertRule
	alerts   []Alert
	alertsMu sync.RWMutex
	
	// Channels
	alertChan chan Alert
	eventChan chan AlertEvent
	stopChan  chan struct{}
	
	// Statistics
	metrics   AlertMetrics
	metricsMu sync.Mutex
	
	// Suppression tracking
	suppressions map[string]time.Time
	suppressMu   sync.Mutex
}

// NewAlertManager creates a new alert manager
func NewAlertManager(config AlertManagerConfig) AlertManager {
	// Set defaults
	if config.MaxAlerts == 0 {
		config.MaxAlerts = 1000
	}
	if config.AlertRetention == 0 {
		config.AlertRetention = time.Hour * 24
	}
	if config.SuppressionWindow == 0 {
		config.SuppressionWindow = time.Minute * 5
	}
	if config.NotificationWorkers == 0 {
		config.NotificationWorkers = 2
	}
	
	am := &alertManagerImpl{
		config:       config,
		rules:        make(map[string]AlertRule),
		alerts:       make([]Alert, 0),
		alertChan:    make(chan Alert, 1000),
		eventChan:    make(chan AlertEvent, 1000),
		stopChan:     make(chan struct{}),
		suppressions: make(map[string]time.Time),
	}
	
	return am
}

// Start begins the alert manager
func (am *alertManagerImpl) Start(ctx context.Context) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	if am.running {
		return fmt.Errorf("alert manager already running")
	}
	
	am.running = true
	
	// Start event processing goroutine
	go am.eventProcessor()
	
	// Start notification workers
	for i := 0; i < am.config.NotificationWorkers; i++ {
		go am.notificationWorker(i)
	}
	
	// Start cleanup goroutine
	go am.cleanupWorker()
	
	return nil
}

// Stop halts the alert manager
func (am *alertManagerImpl) Stop() error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	if !am.running {
		return nil
	}
	
	// Signal workers to stop
	close(am.stopChan)
	
	am.running = false
	
	return nil
}

// Close releases resources
func (am *alertManagerImpl) Close() error {
	return am.Stop()
}

// IsRunning returns whether the alert manager is active
func (am *alertManagerImpl) IsRunning() bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.running
}

// AddRule adds a new alert rule
func (am *alertManagerImpl) AddRule(rule AlertRule) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	if rule.Name == "" {
		return fmt.Errorf("rule name cannot be empty")
	}
	
	am.rules[rule.Name] = rule
	
	am.updateMetrics(func(metrics *AlertMetrics) {
		metrics.RulesActive = len(am.rules)
	})
	
	return nil
}

// RemoveRule removes an alert rule
func (am *alertManagerImpl) RemoveRule(name string) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	delete(am.rules, name)
	
	am.updateMetrics(func(metrics *AlertMetrics) {
		metrics.RulesActive = len(am.rules)
	})
	
	return nil
}

// ProcessEvent processes an event for alert evaluation
func (am *alertManagerImpl) ProcessEvent(event AlertEvent) error {
	am.mu.RLock()
	running := am.running
	am.mu.RUnlock()
	
	if !running {
		return fmt.Errorf("alert manager not running")
	}
	
	// Send event to processing channel (non-blocking)
	select {
	case am.eventChan <- event:
		am.updateMetrics(func(metrics *AlertMetrics) {
			metrics.EventsProcessed++
		})
		return nil
	default:
		return fmt.Errorf("event channel full")
	}
}

// eventProcessor handles incoming events
func (am *alertManagerImpl) eventProcessor() {
	for {
		select {
		case <-am.stopChan:
			return
		case event := <-am.eventChan:
			am.processEvent(event)
		}
	}
}

// processEvent evaluates an event against all rules
func (am *alertManagerImpl) processEvent(event AlertEvent) {
	am.mu.RLock()
	rules := make(map[string]AlertRule)
	for k, v := range am.rules {
		rules[k] = v
	}
	am.mu.RUnlock()
	
	for _, rule := range rules {
		if rule.Evaluate(event) {
			// Check suppression
			if am.isSuppressed(rule.Name) {
				am.updateMetrics(func(metrics *AlertMetrics) {
					metrics.SuppressionHits++
				})
				continue
			}
			
			// Create alert
			alert := Alert{
				ID:        am.generateAlertID(),
				Rule:      rule.Name,
				Severity:  rule.Severity,
				Message:   am.formatAlertMessage(rule, event),
				Timestamp: time.Now(),
				Event:     event,
				Actions:   rule.Actions,
			}
			
			// Add to suppression if configured
			if rule.Suppression > 0 {
				am.addSuppression(rule.Name, rule.Suppression)
			}
			
			// Store alert
			am.storeAlert(alert)
			
			// Send to notification channel
			select {
			case am.alertChan <- alert:
			default:
				// Alert channel full
			}
		}
	}
}

// isSuppressed checks if a rule is currently suppressed
func (am *alertManagerImpl) isSuppressed(ruleName string) bool {
	am.suppressMu.Lock()
	defer am.suppressMu.Unlock()
	
	suppressUntil, exists := am.suppressions[ruleName]
	if !exists {
		return false
	}
	
	if time.Now().After(suppressUntil) {
		delete(am.suppressions, ruleName)
		return false
	}
	
	return true
}

// addSuppression adds a rule to suppression
func (am *alertManagerImpl) addSuppression(ruleName string, duration time.Duration) {
	am.suppressMu.Lock()
	defer am.suppressMu.Unlock()
	
	am.suppressions[ruleName] = time.Now().Add(duration)
}

// storeAlert stores an alert in memory
func (am *alertManagerImpl) storeAlert(alert Alert) {
	am.alertsMu.Lock()
	defer am.alertsMu.Unlock()
	
	// Add to alerts list
	am.alerts = append(am.alerts, alert)
	
	// Enforce max alerts limit
	if len(am.alerts) > am.config.MaxAlerts {
		// Remove oldest alerts
		excess := len(am.alerts) - am.config.MaxAlerts
		am.alerts = am.alerts[excess:]
	}
	
	am.updateMetrics(func(metrics *AlertMetrics) {
		metrics.TotalAlerts++
	})
}

// notificationWorker handles alert notifications
func (am *alertManagerImpl) notificationWorker(id int) {
	for {
		select {
		case <-am.stopChan:
			return
		case alert := <-am.alertChan:
			am.handleAlertActions(alert)
		}
	}
}

// handleAlertActions executes actions for an alert
func (am *alertManagerImpl) handleAlertActions(alert Alert) {
	for _, action := range alert.Actions {
		switch action.Type {
		case "log":
			am.handleLogAction(alert, action)
		case "webhook":
			am.handleWebhookAction(alert, action)
		case "email":
			am.handleEmailAction(alert, action)
		}
	}
}

// handleLogAction logs an alert
func (am *alertManagerImpl) handleLogAction(alert Alert, action AlertAction) {
	level := "info"
	if levelVal, ok := action.Config["level"]; ok {
		level = levelVal.(string)
	}
	
	fmt.Printf("[%s] ALERT: %s - %s (Rule: %s)\n", 
		level, alert.Severity, alert.Message, alert.Rule)
}

// handleWebhookAction sends alert via webhook
func (am *alertManagerImpl) handleWebhookAction(alert Alert, action AlertAction) {
	url, ok := action.Config["url"].(string)
	if !ok {
		return
	}
	
	timeout := time.Second * 5
	if timeoutStr, ok := action.Config["timeout"].(string); ok {
		if parsed, err := time.ParseDuration(timeoutStr); err == nil {
			timeout = parsed
		}
	}
	
	// Prepare payload
	payload, err := json.Marshal(alert)
	if err != nil {
		return
	}
	
	// Create HTTP client with timeout
	client := &http.Client{Timeout: timeout}
	
	// Send POST request
	_, err = client.Post(url, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		// Log webhook error (in production, might want to retry)
		fmt.Printf("Webhook error: %v\n", err)
	}
}

// handleEmailAction sends alert via email (placeholder)
func (am *alertManagerImpl) handleEmailAction(alert Alert, action AlertAction) {
	// Email implementation would go here
	fmt.Printf("EMAIL ALERT: %s\n", alert.Message)
}

// cleanupWorker periodically cleans up old alerts
func (am *alertManagerImpl) cleanupWorker() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	
	for {
		select {
		case <-am.stopChan:
			return
		case <-ticker.C:
			am.cleanupOldAlerts()
		}
	}
}

// cleanupOldAlerts removes alerts older than retention period
func (am *alertManagerImpl) cleanupOldAlerts() {
	cutoff := time.Now().Add(-am.config.AlertRetention)
	
	am.alertsMu.Lock()
	defer am.alertsMu.Unlock()
	
	var kept []Alert
	for _, alert := range am.alerts {
		if alert.Timestamp.After(cutoff) {
			kept = append(kept, alert)
		}
	}
	
	am.alerts = kept
}

// ForceCleanup manually triggers cleanup for testing
func (am *alertManagerImpl) ForceCleanup() {
	am.cleanupOldAlerts()
}

// formatAlertMessage creates a human-readable alert message
func (am *alertManagerImpl) formatAlertMessage(rule AlertRule, event AlertEvent) string {
	return fmt.Sprintf("Rule '%s' triggered: %s = %v (threshold: %v)", 
		rule.Name, event.Type, event.Value, rule.Threshold)
}

// generateAlertID creates a unique alert ID
func (am *alertManagerImpl) generateAlertID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// updateMetrics safely updates alert metrics
func (am *alertManagerImpl) updateMetrics(update func(*AlertMetrics)) {
	am.metricsMu.Lock()
	defer am.metricsMu.Unlock()
	update(&am.metrics)
}

// Alerts returns the alerts channel
func (am *alertManagerImpl) Alerts() <-chan Alert {
	return am.alertChan
}

// GetMetrics returns current alert metrics
func (am *alertManagerImpl) GetMetrics() AlertMetrics {
	am.metricsMu.Lock()
	defer am.metricsMu.Unlock()
	
	am.mu.RLock()
	metrics := am.metrics
	metrics.RulesActive = len(am.rules)
	am.mu.RUnlock()
	
	return metrics
}

// GetMaxAlerts returns the maximum number of alerts
func (am *alertManagerImpl) GetMaxAlerts() int {
	return am.config.MaxAlerts
}

// GetRecentAlerts returns alerts from the specified duration
func (am *alertManagerImpl) GetRecentAlerts(duration time.Duration) []Alert {
	cutoff := time.Now().Add(-duration)
	
	am.alertsMu.RLock()
	defer am.alertsMu.RUnlock()
	
	var recent []Alert
	for _, alert := range am.alerts {
		if alert.Timestamp.After(cutoff) {
			recent = append(recent, alert)
		}
	}
	
	return recent
}