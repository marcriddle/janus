# Janus Phase 3: NAT Detection and Analysis

## Overview

Phase 3 of Janus adds advanced Network Address Translation (NAT) detection and analysis capabilities. This phase enables Janus to identify and analyze various NAT scenarios, including:

- Source NAT (SNAT)
- Destination NAT (DNAT)
- Port Address Translation (PAT)
- Carrier-Grade NAT (CGNAT)
- Double NAT scenarios
- Load balancer transformations
- Hairpin NAT

## Building with Phase 3 Features

To build Janus with Phase 3 NAT analysis features:

```bash
go build -tags phase3 ./cmd/janus/
```

## Usage

### Basic NAT Detection

Analyze two capture files for NAT transformations:

```bash
./janus -pcap1 internal.pcap -pcap2 external.pcap -nat
```

### Detailed NAT Report

Generate a comprehensive NAT analysis report:

```bash
./janus -pcap1 internal.pcap -pcap2 external.pcap -nat -nat-report
```

### Multi-Point NAT Analysis

Analyze NAT across multiple capture points:

```bash
./janus -pcap lan.pcap -pcap dmz.pcap -pcap wan.pcap \
        -point LAN -point DMZ -point WAN \
        -nat -nat-report
```

### Generate NAT Visualization

Create a Graphviz diagram of NAT flows:

```bash
./janus -pcap1 internal.pcap -pcap2 external.pcap \
        -nat -nat-graphviz nat-flows.dot

# Convert to PNG
dot -Tpng nat-flows.dot -o nat-diagram.png
```

## Command-Line Options

### NAT-Specific Options

- `-nat`: Enable NAT detection and analysis
- `-nat-report`: Generate detailed NAT analysis report
- `-nat-graphviz <file>`: Generate Graphviz output for NAT flows
- `-detect-cgnat`: Enable CGNAT detection (default: true)

### General Options

- `-pcap <file>`: PCAP file to analyze (can be specified multiple times)
- `-point <name>`: Capture point name (matches order of -pcap flags)
- `-verbose`: Enable verbose output
- `-output <file>`: Output file for results (default: stdout)

### Legacy Options (for compatibility)

- `-pcap1 <file>`: First PCAP file
- `-pcap2 <file>`: Second PCAP file
- `-point1 <name>`: Name for first capture point
- `-point2 <name>`: Name for second capture point

## NAT Analysis Output

### Summary Section

The NAT analysis provides:
- Total flows analyzed
- Number and percentage of NAT-modified flows
- Detection confidence score
- Key findings about NAT behavior

### Detailed Report

When using `-nat-report`, the output includes:

1. **Executive Summary**
   - Analysis duration
   - Flow statistics
   - Top findings

2. **NAT Detection Results**
   - NAT type distribution
   - Special scenarios (Double NAT, CGNAT)

3. **Connection Tracking Analysis**
   - Active/expired connections
   - Protocol distribution
   - Symmetric vs asymmetric flows

4. **NAT Behavior Analysis**
   - Port preservation rates
   - Connection duration patterns
   - Behavioral insights

5. **Detailed NAT Entries**
   - Top flows by packet count
   - Full transformation details

6. **Recommendations**
   - Network configuration suggestions
   - Performance optimization tips

## Example Output

```
Janus NAT Analysis
==================

NAT Detection Summary:
---------------------
Capture points: internal.pcap <-> external.pcap
Total flows analyzed: 150
NAT-modified flows: 125 (83.3%)
Direct NAT detections: 125
Detection confidence: 92.5%

Key Findings:
  • Analyzed 150 flows, 125 (83.3%) show NAT transformation
  • Source NAT detected in 120 flows
  • Carrier-Grade NAT (CGNAT) detected in 5 flows - typical of ISP networks
  • 95.0% of flows show bidirectional traffic

NAT Behavior Analysis:
  • Active connections: 45
  • Average connection duration: 2m15s
  • High port preservation rate (85.0%) - indicates endpoint-independent NAT
  • Predominantly Source NAT behavior (96.0% of connections)
```

## Implementation Details

Phase 3 introduces several new components:

### NAT Detector (`pkg/nat/detector.go`)
- Identifies NAT transformations between packet pairs
- Maintains NAT translation tables
- Detects complex scenarios (double NAT, CGNAT)

### Flow Transformer (`pkg/nat/transformer.go`)
- Analyzes specific transformation types
- Implements rule-based transformation detection
- Supports custom transformation rules

### Connection Tracker (`pkg/nat/tracker.go`)
- Stateful connection tracking
- TCP state machine implementation
- NAT behavior analysis

### NAT Reporter (`pkg/nat/reporter.go`)
- Human-readable report generation
- Graphviz visualization support
- Statistical analysis and recommendations

## Use Cases

1. **Network Troubleshooting**
   - Identify NAT-related connectivity issues
   - Detect double NAT scenarios
   - Analyze NAT timeout behaviors

2. **Security Analysis**
   - Track connection flows through NAT devices
   - Identify asymmetric routing
   - Detect NAT traversal attempts

3. **Performance Optimization**
   - Analyze NAT device behavior
   - Identify port exhaustion risks
   - Optimize NAT configurations

4. **Network Planning**
   - Understand NAT deployment patterns
   - Plan for IPv6 migration
   - Capacity planning for NAT devices