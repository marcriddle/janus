package nat

import (
	"fmt"
	"net"
	"sync"

	"github.com/janus-project/janus/pkg/types"
)

// TransformationRule represents a rule for identifying specific transformations
type TransformationRule struct {
	Name        string
	Description string
	Matcher     func(*types.CapturePointInfo, *types.CapturePointInfo) bool
	Transform   func(*types.CapturePointInfo, *types.CapturePointInfo) *Transformation
}

// Transformation represents a detected packet transformation
type Transformation struct {
	Type        string
	Description string
	Fields      map[string]interface{}
	Confidence  float64
}

// Transformer detects and analyzes packet transformations
type Transformer struct {
	rules []TransformationRule
	mu    sync.RWMutex
}

// NewTransformer creates a new transformation detector
func NewTransformer() *Transformer {
	t := &Transformer{
		rules: []TransformationRule{},
	}
	
	// Register default transformation rules
	t.registerDefaultRules()
	
	return t
}

// registerDefaultRules sets up the default transformation detection rules
func (t *Transformer) registerDefaultRules() {
	// Source NAT detection
	t.AddRule(TransformationRule{
		Name:        "source_nat",
		Description: "Source IP/Port modification",
		Matcher: func(p1, p2 *types.CapturePointInfo) bool {
			return !p1.Packet.SrcIP.Equal(p2.Packet.SrcIP) || p1.Packet.SrcPort != p2.Packet.SrcPort
		},
		Transform: func(p1, p2 *types.CapturePointInfo) *Transformation {
			return &Transformation{
				Type:        "SOURCE_NAT",
				Description: fmt.Sprintf("Source NAT: %s:%d -> %s:%d",
					p1.Packet.SrcIP, p1.Packet.SrcPort,
					p2.Packet.SrcIP, p2.Packet.SrcPort),
				Fields: map[string]interface{}{
					"original_src_ip":    p1.Packet.SrcIP.String(),
					"original_src_port":  p1.Packet.SrcPort,
					"translated_src_ip":  p2.Packet.SrcIP.String(),
					"translated_src_port": p2.Packet.SrcPort,
				},
				Confidence: 0.9,
			}
		},
	})
	
	// Destination NAT detection
	t.AddRule(TransformationRule{
		Name:        "destination_nat",
		Description: "Destination IP/Port modification",
		Matcher: func(p1, p2 *types.CapturePointInfo) bool {
			return !p1.Packet.DstIP.Equal(p2.Packet.DstIP) || p1.Packet.DstPort != p2.Packet.DstPort
		},
		Transform: func(p1, p2 *types.CapturePointInfo) *Transformation {
			return &Transformation{
				Type:        "DESTINATION_NAT",
				Description: fmt.Sprintf("Destination NAT: %s:%d -> %s:%d",
					p1.Packet.DstIP, p1.Packet.DstPort,
					p2.Packet.DstIP, p2.Packet.DstPort),
				Fields: map[string]interface{}{
					"original_dst_ip":    p1.Packet.DstIP.String(),
					"original_dst_port":  p1.Packet.DstPort,
					"translated_dst_ip":  p2.Packet.DstIP.String(),
					"translated_dst_port": p2.Packet.DstPort,
				},
				Confidence: 0.9,
			}
		},
	})
	
	// Port Address Translation (PAT)
	t.AddRule(TransformationRule{
		Name:        "pat",
		Description: "Port Address Translation",
		Matcher: func(p1, p2 *types.CapturePointInfo) bool {
			// Same IP but different port
			return p1.Packet.SrcIP.Equal(p2.Packet.SrcIP) && p1.Packet.SrcPort != p2.Packet.SrcPort
		},
		Transform: func(p1, p2 *types.CapturePointInfo) *Transformation {
			return &Transformation{
				Type:        "PAT",
				Description: fmt.Sprintf("Port translation: %d -> %d", p1.Packet.SrcPort, p2.Packet.SrcPort),
				Fields: map[string]interface{}{
					"original_port":   p1.Packet.SrcPort,
					"translated_port": p2.Packet.SrcPort,
				},
				Confidence: 0.8,
			}
		},
	})
	
	// Masquerading (many-to-one NAT)
	t.AddRule(TransformationRule{
		Name:        "masquerade",
		Description: "IP Masquerading",
		Matcher: func(p1, p2 *types.CapturePointInfo) bool {
			// Private to public IP transformation
			return isPrivateIP(p1.Packet.SrcIP) && !isPrivateIP(p2.Packet.SrcIP)
		},
		Transform: func(p1, p2 *types.CapturePointInfo) *Transformation {
			return &Transformation{
				Type:        "MASQUERADE",
				Description: "Private to public IP masquerading",
				Fields: map[string]interface{}{
					"private_ip": p1.Packet.SrcIP.String(),
					"public_ip":  p2.Packet.SrcIP.String(),
				},
				Confidence: 0.95,
			}
		},
	})
	
	// Load balancing detection
	t.AddRule(TransformationRule{
		Name:        "load_balancer",
		Description: "Load balancer transformation",
		Matcher: func(p1, p2 *types.CapturePointInfo) bool {
			// Same source, different destination (typical of load balancers)
			return p1.Packet.SrcIP.Equal(p2.Packet.SrcIP) &&
				p1.Packet.SrcPort == p2.Packet.SrcPort &&
				(!p1.Packet.DstIP.Equal(p2.Packet.DstIP) || p1.Packet.DstPort != p2.Packet.DstPort)
		},
		Transform: func(p1, p2 *types.CapturePointInfo) *Transformation {
			return &Transformation{
				Type:        "LOAD_BALANCER",
				Description: "Load balancer redirection detected",
				Fields: map[string]interface{}{
					"vip":          p1.Packet.DstIP.String(),
					"vip_port":     p1.Packet.DstPort,
					"backend_ip":   p2.Packet.DstIP.String(),
					"backend_port": p2.Packet.DstPort,
				},
				Confidence: 0.85,
			}
		},
	})
	
	// Hairpin NAT detection
	t.AddRule(TransformationRule{
		Name:        "hairpin_nat",
		Description: "Hairpin/Loopback NAT",
		Matcher: func(p1, p2 *types.CapturePointInfo) bool {
			// Source and destination in same network, but transformed
			return isSameNetwork(p1.Packet.SrcIP, p1.Packet.DstIP) &&
				(!p1.Packet.SrcIP.Equal(p2.Packet.SrcIP) || !p1.Packet.DstIP.Equal(p2.Packet.DstIP))
		},
		Transform: func(p1, p2 *types.CapturePointInfo) *Transformation {
			return &Transformation{
				Type:        "HAIRPIN_NAT",
				Description: "Hairpin NAT detected (internal to internal via NAT)",
				Fields: map[string]interface{}{
					"internal_src": p1.Packet.SrcIP.String(),
					"internal_dst": p1.Packet.DstIP.String(),
					"nat_src":      p2.Packet.SrcIP.String(),
					"nat_dst":      p2.Packet.DstIP.String(),
				},
				Confidence: 0.75,
			}
		},
	})
}

// AddRule adds a new transformation detection rule
func (t *Transformer) AddRule(rule TransformationRule) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rules = append(t.rules, rule)
}

// DetectTransformations analyzes two packets and detects all transformations
func (t *Transformer) DetectTransformations(p1, p2 *types.CapturePointInfo) []Transformation {
	t.mu.RLock()
	defer t.mu.RUnlock()
	
	transformations := []Transformation{}
	
	for _, rule := range t.rules {
		if rule.Matcher(p1, p2) {
			if transform := rule.Transform(p1, p2); transform != nil {
				transformations = append(transformations, *transform)
			}
		}
	}
	
	return transformations
}

// AnalyzeFlowTransformations analyzes transformations across an entire flow
func (t *Transformer) AnalyzeFlowTransformations(packets []*types.CapturePointInfo) *FlowTransformationAnalysis {
	if len(packets) < 2 {
		return &FlowTransformationAnalysis{
			TotalPackets: len(packets),
		}
	}
	
	analysis := &FlowTransformationAnalysis{
		TotalPackets:     len(packets),
		Transformations:  []Transformation{},
		UniqueTransforms: make(map[string]int),
	}
	
	// Analyze consecutive packet pairs
	for i := 0; i < len(packets)-1; i++ {
		transforms := t.DetectTransformations(packets[i], packets[i+1])
		analysis.Transformations = append(analysis.Transformations, transforms...)
		
		// Count unique transformation types
		for _, transform := range transforms {
			analysis.UniqueTransforms[transform.Type]++
		}
	}
	
	// Identify patterns
	analysis.Patterns = t.identifyPatterns(analysis)
	
	return analysis
}

// identifyPatterns looks for patterns in transformations
func (t *Transformer) identifyPatterns(analysis *FlowTransformationAnalysis) []string {
	patterns := []string{}
	
	// Consistent NAT pattern
	if count, exists := analysis.UniqueTransforms["SOURCE_NAT"]; exists && count > 5 {
		patterns = append(patterns, "Consistent source NAT throughout flow")
	}
	
	// Load balancing pattern
	if count, exists := analysis.UniqueTransforms["LOAD_BALANCER"]; exists && count > 0 {
		patterns = append(patterns, "Load balancing detected in flow")
	}
	
	// Multiple transformation types
	if len(analysis.UniqueTransforms) > 2 {
		patterns = append(patterns, "Complex transformation chain detected")
	}
	
	// Hairpin NAT
	if _, exists := analysis.UniqueTransforms["HAIRPIN_NAT"]; exists {
		patterns = append(patterns, "Internal traffic routed through NAT device")
	}
	
	return patterns
}

// FlowTransformationAnalysis contains the analysis results for a flow
type FlowTransformationAnalysis struct {
	TotalPackets     int
	Transformations  []Transformation
	UniqueTransforms map[string]int
	Patterns         []string
}

// Helper functions

func isPrivateIP(ip net.IP) bool {
	privateRanges := []*net.IPNet{
		{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
		{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)},
		{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(16, 32)},
	}
	
	for _, privateRange := range privateRanges {
		if privateRange.Contains(ip) {
			return true
		}
	}
	return false
}

func isSameNetwork(ip1, ip2 net.IP) bool {
	// Simple check - same /24 network
	return ip1.Mask(net.CIDRMask(24, 32)).Equal(ip2.Mask(net.CIDRMask(24, 32)))
}