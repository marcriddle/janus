# Janus

Traces network packets across multiple capture points to instantly diagnose flow issues.

## Overview

Janus is a network diagnostics tool that correlates packet captures (PCAP files) from multiple points in your network infrastructure to trace packet paths and identify where packets are modified or lost.

## Features

### Phase 1 (Complete)
- **Two-point packet correlation**: Compare packets between two capture points
- **IP ID-based matching**: Uses IPv4 Identification field for packet correlation
- **Latency measurement**: Calculate inter-point latency for correlated packets
- **TTL analysis**: Detect routing hops via TTL decrements
- **Basic NAT detection**: Identify when packets undergo address translation

### Phase 2 (Complete)
- **TCP Stream Reassembly**: Full TCP stream reconstruction and analysis
- **Payload Hashing**: Content-based correlation resilient to NAT and header modifications
- **Multi-Strategy Matching**: Automatic selection of best correlation method
- **Re-segmentation Handling**: Detects when packets are fragmented differently
- **Enhanced NAT Detection**: Works even with heavily modified packets

## Installation

```bash
# Clone the repository
git clone https://github.com/janus-project/janus.git
cd janus

# Build the project
make build

# Or install to $GOPATH/bin
make install
```

## Usage

```bash
janus -pcap1 <file1> -pcap2 <file2> [options]

Options:
  -pcap1 string       First PCAP file
  -pcap2 string       Second PCAP file
  -point1 string      Name for first capture point (default: filename)
  -point2 string      Name for second capture point (default: filename)
  -verbose            Enable verbose output
  -stream             Enable TCP stream reassembly mode (Phase 2)
  -skip-ttl-only      Skip displaying packets that differ only by TTL (by 1 hop)

Examples:
  # Basic packet correlation (Phase 1)
  janus -pcap1 container.pcap -pcap2 host.pcap -point1 container -point2 host
  
  # Advanced stream-based correlation (Phase 2)
  janus -pcap1 container.pcap -pcap2 host.pcap -stream -verbose
```

## Development

```bash
# Run tests
make test

# Run tests with coverage
make test-coverage

# Format code
make fmt

# Build
make build
```

## Requirements

- Go 1.19 or later
- libpcap (for packet capture reading)

## Architecture

The tool follows a modular architecture:

- `pkg/types`: Core data structures (FlowKey, PacketInfo, etc.)
- `pkg/pcap`: PCAP file reading and packet parsing
- `pkg/correlator`: Packet correlation engine
- `cmd/janus`: CLI interface

## Roadmap

- [x] Phase 1: Two-point correlator with IP ID matching
- [x] Phase 2: TCP stream reassembly and payload hashing
- [x] Phase 3: Advanced NAT detection and flow transformation tracking
- [ ] Phase 4: N-point correlation and performance optimization

## Phase 3: NAT Detection (Available)

Phase 3 adds comprehensive NAT analysis capabilities. Build with:

```bash
go build -tags phase3 ./cmd/janus/
```

Features:
- Advanced NAT type detection (SNAT, DNAT, PAT, CGNAT)
- Stateful connection tracking
- NAT behavior analysis
- Detailed reporting and visualization

See [docs/phase3-usage.md](docs/phase3-usage.md) for detailed usage.

## Current Limitations

- Only supports IPv4 packets (IPv6 planned for Phase 4)
- Requires time synchronization between capture hosts (PTP recommended)
- TCP stream reassembly requires sufficient memory for large flows
- UDP flows rely on header-based correlation only

## Contributing

See [docs/Janus.md](docs/Janus.md) for the full feasibility study and implementation guide.
