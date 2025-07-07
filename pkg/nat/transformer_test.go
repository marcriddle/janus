package nat

import (
	"net"
	"testing"

	"github.com/janus-project/janus/pkg/types"
)

func TestTransformer_DetectTransformations(t *testing.T) {
	transformer := NewTransformer()
	
	tests := []struct {
		name          string
		p1            *types.CapturePointInfo
		p2            *types.CapturePointInfo
		wantTransform []string // Expected transformation types
	}{
		{
			name: "Source NAT transformation",
			p1: &types.CapturePointInfo{
				Packet: types.PacketInfo{
					SrcIP:   net.ParseIP("192.168.1.100"),
					SrcPort: 45678,
					DstIP:   net.ParseIP("8.8.8.8"),
					DstPort: 443,
				},
			},
			p2: &types.CapturePointInfo{
				Packet: types.PacketInfo{
					SrcIP:   net.ParseIP("203.0.113.1"),
					SrcPort: 23456,
					DstIP:   net.ParseIP("8.8.8.8"),
					DstPort: 443,
				},
			},
			wantTransform: []string{"SOURCE_NAT", "MASQUERADE"},
		},
		{
			name: "Destination NAT transformation",
			p1: &types.CapturePointInfo{
				Packet: types.PacketInfo{
					SrcIP:   net.ParseIP("8.8.8.8"),
					SrcPort: 443,
					DstIP:   net.ParseIP("203.0.113.1"),
					DstPort: 8080,
				},
			},
			p2: &types.CapturePointInfo{
				Packet: types.PacketInfo{
					SrcIP:   net.ParseIP("8.8.8.8"),
					SrcPort: 443,
					DstIP:   net.ParseIP("192.168.1.100"),
					DstPort: 80,
				},
			},
			wantTransform: []string{"DESTINATION_NAT"},
		},
		{
			name: "Port Address Translation",
			p1: &types.CapturePointInfo{
				Packet: types.PacketInfo{
					SrcIP:   net.ParseIP("192.168.1.100"),
					SrcPort: 45678,
					DstIP:   net.ParseIP("8.8.8.8"),
					DstPort: 443,
				},
			},
			p2: &types.CapturePointInfo{
				Packet: types.PacketInfo{
					SrcIP:   net.ParseIP("192.168.1.100"),
					SrcPort: 23456,
					DstIP:   net.ParseIP("8.8.8.8"),
					DstPort: 443,
				},
			},
			wantTransform: []string{"PAT", "SOURCE_NAT"},
		},
		{
			name: "Load balancer transformation",
			p1: &types.CapturePointInfo{
				Packet: types.PacketInfo{
					SrcIP:   net.ParseIP("203.0.113.100"),
					SrcPort: 54321,
					DstIP:   net.ParseIP("198.51.100.1"),
					DstPort: 80,
				},
			},
			p2: &types.CapturePointInfo{
				Packet: types.PacketInfo{
					SrcIP:   net.ParseIP("203.0.113.100"),
					SrcPort: 54321,
					DstIP:   net.ParseIP("192.168.10.20"),
					DstPort: 8080,
				},
			},
			wantTransform: []string{"DESTINATION_NAT", "LOAD_BALANCER"},
		},
		{
			name: "Hairpin NAT",
			p1: &types.CapturePointInfo{
				Packet: types.PacketInfo{
					SrcIP:   net.ParseIP("192.168.1.100"),
					SrcPort: 45678,
					DstIP:   net.ParseIP("192.168.1.200"),
					DstPort: 80,
				},
			},
			p2: &types.CapturePointInfo{
				Packet: types.PacketInfo{
					SrcIP:   net.ParseIP("203.0.113.1"),
					SrcPort: 23456,
					DstIP:   net.ParseIP("192.168.1.200"),
					DstPort: 80,
				},
			},
			wantTransform: []string{"SOURCE_NAT", "HAIRPIN_NAT"},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transformations := transformer.DetectTransformations(tt.p1, tt.p2)
			
			if len(transformations) == 0 {
				t.Error("DetectTransformations() found no transformations")
				return
			}
			
			// Check that expected transformations were found
			foundTypes := make(map[string]bool)
			for _, trans := range transformations {
				foundTypes[trans.Type] = true
			}
			
			for _, expectedType := range tt.wantTransform {
				if !foundTypes[expectedType] {
					t.Errorf("DetectTransformations() missing expected type %s", expectedType)
				}
			}
			
			// Verify confidence scores
			for _, trans := range transformations {
				if trans.Confidence < 0 || trans.Confidence > 1 {
					t.Errorf("Invalid confidence score: %f", trans.Confidence)
				}
			}
		})
	}
}

func TestTransformer_AnalyzeFlowTransformations(t *testing.T) {
	transformer := NewTransformer()
	
	// Create a flow with multiple packets showing transformations
	packets := []*types.CapturePointInfo{
		{
			Packet: types.PacketInfo{
				SrcIP:   net.ParseIP("192.168.1.100"),
				SrcPort: 45678,
				DstIP:   net.ParseIP("8.8.8.8"),
				DstPort: 443,
			},
		},
		{
			Packet: types.PacketInfo{
				SrcIP:   net.ParseIP("10.0.0.100"),
				SrcPort: 34567,
				DstIP:   net.ParseIP("8.8.8.8"),
				DstPort: 443,
			},
		},
		{
			Packet: types.PacketInfo{
				SrcIP:   net.ParseIP("203.0.113.1"),
				SrcPort: 23456,
				DstIP:   net.ParseIP("8.8.8.8"),
				DstPort: 443,
			},
		},
	}
	
	analysis := transformer.AnalyzeFlowTransformations(packets)
	
	if analysis.TotalPackets != 3 {
		t.Errorf("AnalyzeFlowTransformations() TotalPackets = %d, want 3", 
			analysis.TotalPackets)
	}
	
	if len(analysis.Transformations) == 0 {
		t.Error("AnalyzeFlowTransformations() found no transformations")
	}
	
	// Check for complex transformation pattern
	complexPattern := false
	for _, pattern := range analysis.Patterns {
		if contains(pattern, "Complex transformation chain") {
			complexPattern = true
			break
		}
	}
	
	if !complexPattern && len(analysis.UniqueTransforms) > 2 {
		t.Error("AnalyzeFlowTransformations() should detect complex transformation chain")
	}
}

func TestTransformer_CustomRule(t *testing.T) {
	transformer := NewTransformer()
	
	// Add a custom transformation rule
	customRuleFired := false
	transformer.AddRule(TransformationRule{
		Name:        "custom_vpn",
		Description: "Custom VPN transformation",
		Matcher: func(p1, p2 *types.CapturePointInfo) bool {
			// Match if source port changes to 1194 (OpenVPN)
			return p2.Packet.SrcPort == 1194 && p1.Packet.SrcPort != 1194
		},
		Transform: func(p1, p2 *types.CapturePointInfo) *Transformation {
			customRuleFired = true
			return &Transformation{
				Type:        "VPN_ENCAPSULATION",
				Description: "Traffic encapsulated in VPN tunnel",
				Fields: map[string]interface{}{
					"original_port": p1.Packet.SrcPort,
					"vpn_port":      p2.Packet.SrcPort,
				},
				Confidence: 0.95,
			}
		},
	})
	
	// Test the custom rule
	p1 := &types.CapturePointInfo{
		Packet: types.PacketInfo{
			SrcIP:   net.ParseIP("192.168.1.100"),
			SrcPort: 45678,
			DstIP:   net.ParseIP("8.8.8.8"),
			DstPort: 443,
		},
	}
	
	p2 := &types.CapturePointInfo{
		Packet: types.PacketInfo{
			SrcIP:   net.ParseIP("203.0.113.1"),
			SrcPort: 1194,
			DstIP:   net.ParseIP("8.8.8.8"),
			DstPort: 443,
		},
	}
	
	transformations := transformer.DetectTransformations(p1, p2)
	
	if !customRuleFired {
		t.Error("Custom rule did not fire")
	}
	
	// Verify custom transformation is detected
	vpnFound := false
	for _, trans := range transformations {
		if trans.Type == "VPN_ENCAPSULATION" {
			vpnFound = true
			if trans.Confidence != 0.95 {
				t.Errorf("Custom transformation confidence = %f, want 0.95", 
					trans.Confidence)
			}
			break
		}
	}
	
	if !vpnFound {
		t.Error("Custom VPN transformation not found in results")
	}
}

func TestHelperFunctions(t *testing.T) {
	tests := []struct {
		name     string
		ip       net.IP
		wantPriv bool
	}{
		{"10.x.x.x", net.ParseIP("10.1.2.3"), true},
		{"172.16.x.x", net.ParseIP("172.16.1.1"), true},
		{"192.168.x.x", net.ParseIP("192.168.1.1"), true},
		{"Public IP", net.ParseIP("8.8.8.8"), false},
		{"172.32.x.x", net.ParseIP("172.32.1.1"), false}, // Outside private range
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPrivateIP(tt.ip); got != tt.wantPriv {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.wantPriv)
			}
		})
	}
	
	// Test isSameNetwork
	ip1 := net.ParseIP("192.168.1.100")
	ip2 := net.ParseIP("192.168.1.200")
	ip3 := net.ParseIP("192.168.2.100")
	
	if !isSameNetwork(ip1, ip2) {
		t.Error("isSameNetwork() should return true for IPs in same /24")
	}
	
	if isSameNetwork(ip1, ip3) {
		t.Error("isSameNetwork() should return false for IPs in different /24")
	}
}