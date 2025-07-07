# Janus

Traces network packets across multiple capture points to instantly diagnose flow issues.

## Overview

Janus is a network diagnostics tool that correlates packet captures (PCAP files) from multiple points in your network infrastructure to trace packet paths and identify where packets are modified or lost.

## Features (Phase 1)

- **Two-point packet correlation**: Compare packets between two capture points
- **IP ID-based matching**: Uses IPv4 Identification field for packet correlation
- **Latency measurement**: Calculate inter-point latency for correlated packets
- **TTL analysis**: Detect routing hops via TTL decrements
- **Basic NAT detection**: Identify when packets undergo address translation

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
  -pcap1 string    First PCAP file
  -pcap2 string    Second PCAP file
  -point1 string   Name for first capture point (default: filename)
  -point2 string   Name for second capture point (default: filename)
  -verbose         Enable verbose output

Example:
  janus -pcap1 container.pcap -pcap2 host.pcap -point1 container -point2 host
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
- [ ] Phase 2: TCP stream reassembly and payload hashing
- [ ] Phase 3: Advanced NAT detection
- [ ] Phase 4: N-point correlation and performance optimization

## Limitations (Phase 1)

- Only supports IPv4 packets
- Simple IP ID matching may miss packets with ID collisions
- NAT detection is basic and may not catch all transformations
- Requires time synchronization between capture hosts

## Contributing

See [docs/Janus.md](docs/Janus.md) for the full feasibility study and implementation guide.
