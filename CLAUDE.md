# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Janus is a network diagnostics tool for multi-point packet capture (PCAP) analysis. Currently in the feasibility study phase with comprehensive documentation but no implementation yet.

## Development Status

This project is in the planning phase. The repository contains:
- Comprehensive feasibility study and implementation guide in `docs/Janus.md`
- Brief project description in `README.md`

## Planned Implementation

### Technology Stack
- **Language**: Go
- **Core Library**: gopacket (github.com/google/gopacket)
- **Key Dependencies**:
  - github.com/google/gopacket/pcap
  - github.com/google/gopacket/layers
  - github.com/google/gopacket/reassembly
  - github.com/google/gopacket/tcpassembly

### Architecture Overview

The tool will use a concurrent, stream-oriented architecture:

1. **Ingestion Goroutines**: One per PCAP file for parallel processing
2. **Stream Reassembly**: TCP stream reassembly using gopacket/tcpassembly
3. **Central Correlation Engine**: Single goroutine managing flow state across all capture points
4. **Reporting Module**: Generates human-readable output

### Core Data Structures

Key types to be implemented:
- `FlowKey`: Unique identifier for network flows (5-tuple based)
- `PacketInfo`: Packet characteristics at a specific capture point
- `FlowTrace`: Tracks a single flow across all capture points
- Central correlation map: `map[FlowKey]*FlowTrace`

### Implementation Phases

1. **Phase 1**: Two-point correlator (basic PCAP reading, IP ID matching)
2. **Phase 2**: Stream-aware engine (TCP reassembly, payload hashing)
3. **Phase 3**: NAT detection (automatic detection of packet modifications)
4. **Phase 4**: N-point correlation and performance optimization

## Important Considerations

### Time Synchronization
- High-precision time synchronization is critical (PTP preferred over NTP)
- Hardware timestamping recommended over software timestamping
- Use pcapng format for better timestamp support

### Packet Matching Strategy
Implement multiple correlation techniques in order of cost/reliability:
1. IP ID field matching (IPv4 only)
2. TCP sequence/acknowledgment numbers
3. TTL analysis (corroborative)
4. Payload hashing (most reliable but computationally expensive)

### Name Conflict
"Janus" conflicts with existing projects. Alternative names are being considered (see docs/Janus.md Section 5.2).

## Development Commands

### Building
```bash
make build          # Build the binary to bin/janus
make install        # Install to $GOPATH/bin
make clean          # Clean build artifacts
```

### Testing
```bash
make test           # Run all tests
make test-coverage  # Run tests with coverage report
```

### Code Quality
```bash
make fmt            # Format code
make lint           # Run linter (requires golangci-lint)
make check          # Run fmt, test, and lint
```

## Current Implementation Status

Phase 1 is now complete with:
- Basic PCAP reading and packet decoding
- IP ID-based packet correlation
- Two-point correlation analysis
- CLI interface
- Test coverage for core functionality

### Next Steps for Phase 2
1. Implement TCP stream reassembly using gopacket/tcpassembly
2. Add payload hashing for more robust correlation
3. Handle packet re-segmentation scenarios
4. Improve correlation accuracy beyond simple IP ID matching