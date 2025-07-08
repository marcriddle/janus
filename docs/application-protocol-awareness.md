# Application Protocol Awareness Feature Specification

## Overview

The Application Protocol Awareness feature extends Janus beyond basic packet correlation to provide deep understanding of application-layer protocols. This capability enables correlation and analysis at the semantic level of HTTP requests, DNS queries, TLS handshakes, and other application protocols, providing insights that are crucial for debugging modern microservices and distributed applications.

## Core Capabilities

### Protocol-Specific Correlation
- **HTTP request/response matching**: Correlate HTTP requests across load balancers, proxies, and services
- **DNS query tracking**: Follow DNS queries through recursive resolvers and authoritative servers
- **TLS session analysis**: Track TLS handshakes, certificate validation, and session resumption
- **Database protocol support**: MySQL, PostgreSQL, Redis protocol awareness

### Application Flow Reconstruction
- **Request tracing**: End-to-end request tracking through microservice architectures
- **Session correlation**: Application session tracking across multiple network hops
- **Transaction analysis**: Database transaction correlation and performance analysis
- **API call mapping**: RESTful API and GraphQL request correlation

### Protocol-Aware Anomaly Detection
- **HTTP error correlation**: 4xx/5xx errors tracked across service boundaries
- **DNS resolution failures**: Failed queries and resolution timing analysis
- **TLS handshake failures**: Certificate issues and cipher mismatch detection
- **Performance anomalies**: Request latency and throughput analysis

## Technical Architecture

### Protocol Parser Framework
```
┌─────────────────────────────────────────────────────────────┐
│                Protocol Parser Architecture                  │
├─────────────────────────────────────────────────────────────┤
│  Core Framework                                             │
│  ├─ Parser Registry: Plugin management and discovery        │
│  ├─ Protocol Detection: Automatic protocol identification   │
│  ├─ Stream Reassembly: Application-layer stream building    │
│  └─ Event Generation: Protocol-specific event emission      │
├─────────────────────────────────────────────────────────────┤
│  Protocol Parsers (Pluggable)                              │
│  ├─ HTTP/1.1 & HTTP/2 Parser                               │
│  ├─ DNS Parser (UDP/TCP)                                   │
│  ├─ TLS/SSL Parser                                         │
│  ├─ Database Protocol Parsers (MySQL, PostgreSQL, Redis)   │
│  ├─ gRPC Parser                                            │
│  └─ Custom Protocol Plugin Interface                        │
└─────────────────────────────────────────────────────────────┘
```

### Event-Driven Correlation Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Protocol      │    │   Event Bus     │    │   Correlation   │
│   Parsers       │    │                 │    │    Engine       │
│                 │    │ ┌─────────────┐ │    │                 │
│ ┌─────────────┐ │───▶│ │ HTTP Events │ │───▶│ ┌─────────────┐ │
│ │ HTTP Parser │ │    │ └─────────────┘ │    │ │ HTTP Corr.  │ │
│ └─────────────┘ │    │ ┌─────────────┐ │    │ └─────────────┘ │
│ ┌─────────────┐ │───▶│ │ DNS Events  │ │───▶│ ┌─────────────┐ │
│ │ DNS Parser  │ │    │ └─────────────┘ │    │ │ DNS Corr.   │ │
│ └─────────────┘ │    │ ┌─────────────┐ │    │ └─────────────┘ │
│ ┌─────────────┐ │───▶│ │ TLS Events  │ │───▶│ ┌─────────────┐ │
│ │ TLS Parser  │ │    │ └─────────────┘ │    │ │ TLS Corr.   │ │
│ └─────────────┘ │    │                 │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Implementation Details

### Phase 1: Protocol Parser Framework (6-8 weeks)

#### Core Framework Architecture
```go
// pkg/protocol/framework.go
type ProtocolParser interface {
    Name() string
    DetectProtocol(data []byte) float64  // Confidence 0.0-1.0
    ParseStream(stream *ReassembledStream) ([]ProtocolEvent, error)
    GetSessionTracker() SessionTracker
}

type ProtocolEvent struct {
    Type        EventType         `json:"type"`
    Timestamp   time.Time        `json:"timestamp"`
    Protocol    string           `json:"protocol"`
    Data        interface{}      `json:"data"`
    Metadata    map[string]interface{} `json:"metadata"`
    SourcePoint string           `json:"source_point"`
    FlowKey     types.FlowKey    `json:"flow_key"`
}

type EventType string
const (
    EventTypeRequest     EventType = "request"
    EventTypeResponse    EventType = "response"
    EventTypeHandshake   EventType = "handshake"
    EventTypeError       EventType = "error"
    EventTypeConnection  EventType = "connection"
    EventTypeDisconnection EventType = "disconnection"
)

// Protocol registry and management
type ProtocolRegistry struct {
    parsers    map[string]ProtocolParser
    detectors  []ProtocolParser
    eventBus   *EventBus
    mu         sync.RWMutex
}

func (pr *ProtocolRegistry) RegisterParser(parser ProtocolParser) {
    pr.mu.Lock()
    defer pr.mu.Unlock()
    
    pr.parsers[parser.Name()] = parser
    pr.detectors = append(pr.detectors, parser)
}

func (pr *ProtocolRegistry) DetectAndParse(stream *ReassembledStream) ([]ProtocolEvent, error) {
    // Auto-detect protocol
    bestParser, confidence := pr.detectProtocol(stream.Data)
    if confidence < 0.7 {
        return nil, fmt.Errorf("no suitable parser found (confidence: %.2f)", confidence)
    }
    
    // Parse with detected parser
    events, err := bestParser.ParseStream(stream)
    if err != nil {
        return nil, fmt.Errorf("parsing failed: %w", err)
    }
    
    // Emit events to bus
    for _, event := range events {
        pr.eventBus.Emit(event)
    }
    
    return events, nil
}
```

#### Event Bus System
```go
// pkg/protocol/eventbus.go
type EventBus struct {
    subscribers map[EventType][]EventHandler
    buffer      chan ProtocolEvent
    workers     int
    mu          sync.RWMutex
}

type EventHandler interface {
    HandleEvent(event ProtocolEvent) error
    EventTypes() []EventType
}

type ProtocolCorrelator struct {
    protocol    string
    sessions    map[string]*ProtocolSession
    matcher     EventMatcher
    config      CorrelatorConfig
}

func (pc *ProtocolCorrelator) HandleEvent(event ProtocolEvent) error {
    sessionID := pc.extractSessionID(event)
    
    session, exists := pc.sessions[sessionID]
    if !exists {
        session = pc.createSession(sessionID)
        pc.sessions[sessionID] = session
    }
    
    return session.AddEvent(event)
}

// Session tracking for stateful protocols
type ProtocolSession struct {
    ID              string
    Protocol        string
    Events          []ProtocolEvent
    State           SessionState
    Metadata        map[string]interface{}
    CreatedAt       time.Time
    LastActivity    time.Time
    CorrelatedFlows []types.FlowKey
}
```

### Phase 2: HTTP Protocol Implementation (4-6 weeks)

#### HTTP Parser Implementation
```go
// pkg/protocol/http/parser.go
type HTTPParser struct {
    config HTTPParserConfig
}

type HTTPParserConfig struct {
    MaxRequestSize  int64
    MaxResponseSize int64
    TimeoutSeconds  int
    TrackHeaders    []string
    TrackCookies    bool
}

func (p *HTTPParser) ParseStream(stream *ReassembledStream) ([]ProtocolEvent, error) {
    reader := bufio.NewReader(bytes.NewReader(stream.Data))
    var events []ProtocolEvent
    
    for {
        // Try to parse HTTP request or response
        if req, err := http.ReadRequest(reader); err == nil {
            event := p.parseHTTPRequest(req, stream)
            events = append(events, event)
        } else if resp, err := http.ReadResponse(reader, nil); err == nil {
            event := p.parseHTTPResponse(resp, stream)
            events = append(events, event)
        } else {
            break // No more complete HTTP messages
        }
    }
    
    return events, nil
}

func (p *HTTPParser) parseHTTPRequest(req *http.Request, stream *ReassembledStream) ProtocolEvent {
    // Extract request details
    requestData := HTTPRequestData{
        Method:      req.Method,
        URL:         req.URL.String(),
        Proto:       req.Proto,
        Headers:     extractHeaders(req.Header, p.config.TrackHeaders),
        ContentType: req.Header.Get("Content-Type"),
        UserAgent:   req.Header.Get("User-Agent"),
        Host:        req.Host,
        RequestID:   generateRequestID(req),
    }
    
    // Extract body if present and not too large
    if req.ContentLength > 0 && req.ContentLength < p.config.MaxRequestSize {
        body, _ := io.ReadAll(req.Body)
        requestData.Body = string(body)
        requestData.BodyHash = fmt.Sprintf("%x", sha256.Sum256(body))
    }
    
    return ProtocolEvent{
        Type:        EventTypeRequest,
        Timestamp:   stream.FirstSeen,
        Protocol:    "http",
        Data:        requestData,
        SourcePoint: stream.SourcePoint,
        FlowKey:     stream.FlowKey,
        Metadata: map[string]interface{}{
            "direction": "request",
            "size":      len(stream.Data),
        },
    }
}

type HTTPRequestData struct {
    Method      string            `json:"method"`
    URL         string            `json:"url"`
    Proto       string            `json:"proto"`
    Headers     map[string]string `json:"headers"`
    ContentType string            `json:"content_type"`
    UserAgent   string            `json:"user_agent"`
    Host        string            `json:"host"`
    Body        string            `json:"body,omitempty"`
    BodyHash    string            `json:"body_hash,omitempty"`
    RequestID   string            `json:"request_id"`
}

type HTTPResponseData struct {
    StatusCode  int               `json:"status_code"`
    Status      string            `json:"status"`
    Proto       string            `json:"proto"`
    Headers     map[string]string `json:"headers"`
    ContentType string            `json:"content_type"`
    Body        string            `json:"body,omitempty"`
    BodyHash    string            `json:"body_hash,omitempty"`
    RequestID   string            `json:"request_id"`
}
```

#### HTTP Correlation Logic
```go
// pkg/protocol/http/correlator.go
type HTTPCorrelator struct {
    pendingRequests  map[string]*HTTPRequest
    completedPairs   []HTTPTransaction
    matchTimeout     time.Duration
    mu               sync.Mutex
}

type HTTPRequest struct {
    Event       ProtocolEvent
    Timestamp   time.Time
    RequestID   string
    Method      string
    URL         string
    SourcePoint string
}

type HTTPResponse struct {
    Event       ProtocolEvent
    Timestamp   time.Time
    StatusCode  int
    RequestID   string
    SourcePoint string
}

type HTTPTransaction struct {
    Request      HTTPRequest
    Response     HTTPResponse
    Latency      time.Duration
    Path         []string // Capture points in order
    Successful   bool
    ErrorReason  string
}

func (hc *HTTPCorrelator) HandleEvent(event ProtocolEvent) error {
    hc.mu.Lock()
    defer hc.mu.Unlock()
    
    switch event.Type {
    case EventTypeRequest:
        return hc.handleRequest(event)
    case EventTypeResponse:
        return hc.handleResponse(event)
    default:
        return nil
    }
}

func (hc *HTTPCorrelator) handleRequest(event ProtocolEvent) error {
    data := event.Data.(HTTPRequestData)
    
    req := &HTTPRequest{
        Event:       event,
        Timestamp:   event.Timestamp,
        RequestID:   data.RequestID,
        Method:      data.Method,
        URL:         data.URL,
        SourcePoint: event.SourcePoint,
    }
    
    // Store for later correlation with response
    hc.pendingRequests[data.RequestID] = req
    
    // Clean up old requests
    hc.cleanupExpiredRequests()
    
    return nil
}

func (hc *HTTPCorrelator) handleResponse(event ProtocolEvent) error {
    data := event.Data.(HTTPResponseData)
    
    // Find matching request
    req, exists := hc.pendingRequests[data.RequestID]
    if !exists {
        // Response without matching request - might be partial capture
        return fmt.Errorf("no matching request for response %s", data.RequestID)
    }
    
    // Create transaction
    transaction := HTTPTransaction{
        Request:    *req,
        Response: HTTPResponse{
            Event:       event,
            Timestamp:   event.Timestamp,
            StatusCode:  data.StatusCode,
            RequestID:   data.RequestID,
            SourcePoint: event.SourcePoint,
        },
        Latency:    event.Timestamp.Sub(req.Timestamp),
        Path:       []string{req.SourcePoint, event.SourcePoint},
        Successful: data.StatusCode < 400,
    }
    
    hc.completedPairs = append(hc.completedPairs, transaction)
    delete(hc.pendingRequests, data.RequestID)
    
    return nil
}
```

### Phase 3: DNS and TLS Protocol Support (4-6 weeks)

#### DNS Parser Implementation
```go
// pkg/protocol/dns/parser.go
type DNSParser struct {
    config DNSParserConfig
}

type DNSParserConfig struct {
    TrackQueries    bool
    TrackResponses  bool
    MaxPacketSize   int
    ResolveNames    bool
}

func (p *DNSParser) ParseStream(stream *ReassembledStream) ([]ProtocolEvent, error) {
    var events []ProtocolEvent
    
    // DNS is typically single packet, but handle TCP case
    if stream.Protocol == "udp" {
        event, err := p.parseDNSPacket(stream.Data, stream)
        if err == nil {
            events = append(events, event)
        }
    } else {
        // TCP DNS may have multiple messages
        reader := bytes.NewReader(stream.Data)
        for reader.Len() > 0 {
            var length uint16
            binary.Read(reader, binary.BigEndian, &length)
            
            if reader.Len() < int(length) {
                break
            }
            
            msgData := make([]byte, length)
            reader.Read(msgData)
            
            event, err := p.parseDNSPacket(msgData, stream)
            if err == nil {
                events = append(events, event)
            }
        }
    }
    
    return events, nil
}

func (p *DNSParser) parseDNSPacket(data []byte, stream *ReassembledStream) (ProtocolEvent, error) {
    var msg dns.Msg
    if err := msg.Unpack(data); err != nil {
        return ProtocolEvent{}, err
    }
    
    eventType := EventTypeRequest
    if msg.Response {
        eventType = EventTypeResponse
    }
    
    dnsData := DNSData{
        ID:        msg.Id,
        Opcode:    msg.Opcode,
        Response:  msg.Response,
        Rcode:     msg.Rcode,
        Questions: extractQuestions(msg.Question),
        Answers:   extractAnswers(msg.Answer),
        Authority: extractAnswers(msg.Ns),
        Additional: extractAnswers(msg.Extra),
    }
    
    return ProtocolEvent{
        Type:        eventType,
        Timestamp:   stream.FirstSeen,
        Protocol:    "dns",
        Data:        dnsData,
        SourcePoint: stream.SourcePoint,
        FlowKey:     stream.FlowKey,
        Metadata: map[string]interface{}{
            "query_id":   msg.Id,
            "recursive":  msg.RecursionDesired,
            "authoritative": msg.Authoritative,
        },
    }, nil
}

type DNSData struct {
    ID         uint16      `json:"id"`
    Opcode     int         `json:"opcode"`
    Response   bool        `json:"response"`
    Rcode      int         `json:"rcode"`
    Questions  []DNSQuestion `json:"questions"`
    Answers    []DNSAnswer   `json:"answers"`
    Authority  []DNSAnswer   `json:"authority"`
    Additional []DNSAnswer   `json:"additional"`
}

type DNSQuestion struct {
    Name  string `json:"name"`
    Type  string `json:"type"`
    Class string `json:"class"`
}

type DNSAnswer struct {
    Name  string `json:"name"`
    Type  string `json:"type"`
    Class string `json:"class"`
    TTL   uint32 `json:"ttl"`
    Data  string `json:"data"`
}
```

#### TLS Parser Implementation
```go
// pkg/protocol/tls/parser.go
type TLSParser struct {
    config TLSParserConfig
}

type TLSParserConfig struct {
    TrackHandshakes     bool
    TrackApplicationData bool
    ExtractCertificates bool
    ExtractSNI          bool
}

func (p *TLSParser) ParseStream(stream *ReassembledStream) ([]ProtocolEvent, error) {
    var events []ProtocolEvent
    reader := bytes.NewReader(stream.Data)
    
    for reader.Len() > 0 {
        // Read TLS record header
        var recordType uint8
        var version uint16
        var length uint16
        
        if err := binary.Read(reader, binary.BigEndian, &recordType); err != nil {
            break
        }
        if err := binary.Read(reader, binary.BigEndian, &version); err != nil {
            break
        }
        if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
            break
        }
        
        if reader.Len() < int(length) {
            break
        }
        
        recordData := make([]byte, length)
        reader.Read(recordData)
        
        event, err := p.parseTLSRecord(recordType, version, recordData, stream)
        if err == nil {
            events = append(events, event)
        }
    }
    
    return events, nil
}

func (p *TLSParser) parseTLSRecord(recordType uint8, version uint16, data []byte, stream *ReassembledStream) (ProtocolEvent, error) {
    switch recordType {
    case 22: // Handshake
        return p.parseHandshakeRecord(data, stream)
    case 20: // Change Cipher Spec
        return p.parseChangeCipherSpec(data, stream)
    case 21: // Alert
        return p.parseAlert(data, stream)
    case 23: // Application Data
        return p.parseApplicationData(data, stream)
    default:
        return ProtocolEvent{}, fmt.Errorf("unknown TLS record type: %d", recordType)
    }
}

type TLSHandshakeData struct {
    Type            string              `json:"type"`
    Version         string              `json:"version"`
    Random          string              `json:"random"`
    SessionID       string              `json:"session_id"`
    CipherSuites    []string            `json:"cipher_suites,omitempty"`
    SelectedCipher  string              `json:"selected_cipher,omitempty"`
    Extensions      map[string]interface{} `json:"extensions,omitempty"`
    Certificates    []TLSCertificate    `json:"certificates,omitempty"`
    ServerName      string              `json:"server_name,omitempty"`
}

type TLSCertificate struct {
    Subject         string    `json:"subject"`
    Issuer          string    `json:"issuer"`
    SerialNumber    string    `json:"serial_number"`
    NotBefore       time.Time `json:"not_before"`
    NotAfter        time.Time `json:"not_after"`
    Fingerprint     string    `json:"fingerprint"`
    DNSNames        []string  `json:"dns_names"`
}
```

### Phase 4: Advanced Correlation and Analysis (6-8 weeks)

#### Cross-Protocol Correlation
```go
// pkg/protocol/correlation/cross_protocol.go
type CrossProtocolCorrelator struct {
    httpCorrelator  *HTTPCorrelator
    dnsCorrelator   *DNSCorrelator
    tlsCorrelator   *TLSCorrelator
    transactions    []Transaction
    sessionTracker  *SessionTracker
}

type Transaction struct {
    ID              string                 `json:"id"`
    Type            string                 `json:"type"` // http_request, dns_query, tls_handshake
    StartTime       time.Time              `json:"start_time"`
    EndTime         time.Time              `json:"end_time"`
    Duration        time.Duration          `json:"duration"`
    Success         bool                   `json:"success"`
    ErrorMessage    string                 `json:"error_message,omitempty"`
    Path            []string               `json:"path"`
    Protocols       []string               `json:"protocols"`
    RelatedEvents   []ProtocolEvent        `json:"related_events"`
    Metadata        map[string]interface{} `json:"metadata"`
}

func (cpc *CrossProtocolCorrelator) AnalyzeFlow(flowKey types.FlowKey) (*FlowAnalysis, error) {
    // Collect all protocol events for this flow
    events := cpc.getEventsForFlow(flowKey)
    
    // Group events by transaction boundaries
    transactions := cpc.groupIntoTransactions(events)
    
    // Perform cross-protocol analysis
    analysis := &FlowAnalysis{
        FlowKey:         flowKey,
        Transactions:    transactions,
        ProtocolStack:   cpc.analyzeProtocolStack(events),
        Dependencies:    cpc.analyzeDependencies(transactions),
        PerformanceMetrics: cpc.calculateMetrics(transactions),
        Anomalies:       cpc.detectAnomalies(transactions),
    }
    
    return analysis, nil
}

type FlowAnalysis struct {
    FlowKey            types.FlowKey        `json:"flow_key"`
    Transactions       []Transaction        `json:"transactions"`
    ProtocolStack      []string             `json:"protocol_stack"`
    Dependencies       []Dependency         `json:"dependencies"`
    PerformanceMetrics PerformanceMetrics   `json:"performance_metrics"`
    Anomalies          []Anomaly            `json:"anomalies"`
}

type Dependency struct {
    Type        string    `json:"type"` // dns_lookup, tls_handshake, http_redirect
    Source      string    `json:"source"`
    Target      string    `json:"target"`
    Duration    time.Duration `json:"duration"`
    Critical    bool      `json:"critical"`
}

type PerformanceMetrics struct {
    TotalDuration       time.Duration `json:"total_duration"`
    DNSResolutionTime   time.Duration `json:"dns_resolution_time"`
    TLSHandshakeTime    time.Duration `json:"tls_handshake_time"`
    HTTPResponseTime    time.Duration `json:"http_response_time"`
    RequestsPerSecond   float64       `json:"requests_per_second"`
    ErrorRate           float64       `json:"error_rate"`
}
```

#### Service Mesh Integration
```go
// pkg/protocol/servicemesh/istio.go
type IstioMetadataExtractor struct {
    config IstioConfig
}

type IstioConfig struct {
    ExtractHeaders      bool
    TrackSidecarTraffic bool
    CorrelateWithTraces bool
}

type ServiceMeshMetadata struct {
    SourceService      string            `json:"source_service"`
    DestinationService string            `json:"destination_service"`
    SourceVersion      string            `json:"source_version"`
    DestinationVersion string            `json:"destination_version"`
    Headers            map[string]string `json:"headers"`
    TraceID            string            `json:"trace_id"`
    SpanID             string            `json:"span_id"`
    IstioPolicy        string            `json:"istio_policy"`
}

func (ime *IstioMetadataExtractor) ExtractMetadata(event ProtocolEvent) (*ServiceMeshMetadata, error) {
    if event.Protocol != "http" {
        return nil, fmt.Errorf("istio metadata only available for HTTP")
    }
    
    httpData := event.Data.(HTTPRequestData)
    
    metadata := &ServiceMeshMetadata{
        SourceService:      httpData.Headers["x-envoy-original-dst-host"],
        DestinationService: httpData.Host,
        TraceID:            httpData.Headers["x-trace-id"],
        SpanID:             httpData.Headers["x-span-id"],
        Headers:            ime.extractIstioHeaders(httpData.Headers),
    }
    
    return metadata, nil
}
```

## Development Roadmap

### Milestone 1: Framework Foundation (Week 1-3)
- [ ] Design and implement protocol parser interface
- [ ] Create event bus system with pub/sub pattern
- [ ] Implement automatic protocol detection logic
- [ ] Add session tracking and state management
- [ ] Create plugin system for protocol parsers
- [ ] Unit tests for core framework components

### Milestone 2: HTTP Protocol Support (Week 4-6)
- [ ] Implement HTTP/1.1 request/response parser
- [ ] Add HTTP/2 support with frame handling
- [ ] Create HTTP correlation logic for request/response pairing
- [ ] Implement request ID generation and tracking
- [ ] Add support for chunked encoding and compression
- [ ] Performance testing with high-volume HTTP traffic

### Milestone 3: DNS Protocol Support (Week 7-9)
- [ ] Implement DNS packet parser for UDP and TCP
- [ ] Add DNS query/response correlation
- [ ] Support for all common DNS record types
- [ ] Implement recursive resolution tracking
- [ ] Add DNSSEC validation support
- [ ] Create DNS performance metrics

### Milestone 4: TLS Protocol Support (Week 10-12)
- [ ] Implement TLS record parser
- [ ] Add handshake message parsing
- [ ] Extract certificate information and validation
- [ ] Support for SNI and ALPN extensions
- [ ] Implement session resumption tracking
- [ ] Add cipher suite and security analysis

### Milestone 5: Cross-Protocol Correlation (Week 13-16)
- [ ] Design transaction correlation logic
- [ ] Implement dependency analysis
- [ ] Add performance metric calculation
- [ ] Create anomaly detection algorithms
- [ ] Implement service mesh metadata extraction
- [ ] Add distributed tracing integration

### Milestone 6: Advanced Features (Week 17-20)
- [ ] gRPC protocol support
- [ ] Database protocol parsers (MySQL, PostgreSQL)
- [ ] WebSocket protocol analysis
- [ ] Application performance monitoring integration
- [ ] Machine learning-based anomaly detection
- [ ] Real-time analysis capabilities

## CLI Interface

### Enhanced Command Line Options
```bash
# Enable protocol parsing
janus-phase4 -pcap *.pcap -protocol-decode http,dns,tls

# HTTP-specific analysis
janus-phase4 -pcap *.pcap -http-correlation -track-headers "authorization,x-request-id"

# DNS query tracking
janus-phase4 -pcap *.pcap -dns-resolution-analysis -recursive-tracking

# TLS security analysis
janus-phase4 -pcap *.pcap -tls-analysis -certificate-validation -cipher-analysis

# Service mesh integration
janus-phase4 -pcap *.pcap -service-mesh istio -extract-traces

# Application performance analysis
janus-phase4 -pcap *.pcap -application-metrics -latency-analysis -error-correlation

# Export application-layer data
janus-phase4 -pcap *.pcap -export-http-transactions transactions.json
janus-phase4 -pcap *.pcap -export-dns-queries dns.csv
janus-phase4 -pcap *.pcap -export-tls-sessions tls.json
```

### Configuration File Support
```yaml
# application-protocol-config.yaml
protocols:
  http:
    enabled: true
    track_headers:
      - "authorization"
      - "x-request-id"
      - "user-agent"
    track_cookies: true
    max_body_size: "1MB"
    correlation_timeout: "30s"
    
  dns:
    enabled: true
    track_queries: true
    track_responses: true
    resolve_names: false
    recursive_analysis: true
    
  tls:
    enabled: true
    extract_certificates: true
    validate_certificates: true
    track_cipher_suites: true
    security_analysis: true
    
correlation:
  cross_protocol: true
  transaction_timeout: "60s"
  dependency_analysis: true
  performance_metrics: true
  
service_mesh:
  type: "istio"
  extract_metadata: true
  trace_correlation: true
  
output:
  include_raw_events: false
  group_by_transaction: true
  export_formats:
    - json
    - csv
```

## Technical Considerations

### Performance Requirements
- **Parser Throughput**: Handle 10Gbps HTTP traffic with <10% CPU overhead
- **Memory Efficiency**: <1GB memory usage for 1M concurrent sessions
- **Latency**: <100ms additional latency for protocol parsing
- **Scalability**: Linear scaling with number of worker threads

### Protocol Support Priorities
1. **HTTP/1.1 & HTTP/2**: Essential for web application debugging
2. **DNS**: Critical for resolution troubleshooting
3. **TLS**: Important for security and certificate analysis
4. **gRPC**: Growing importance in microservices
5. **Database protocols**: MySQL, PostgreSQL for data layer analysis

### Security Considerations
- **Sensitive Data**: Optional PII redaction in HTTP bodies
- **Certificate Validation**: Real-time certificate chain validation
- **Audit Logging**: Comprehensive logging of parser actions
- **Data Retention**: Configurable retention for parsed protocol data

## Integration Points

### Observability Platforms
- **OpenTelemetry**: Export traces and metrics in OTEL format
- **Jaeger/Zipkin**: Distributed tracing correlation
- **Prometheus**: Performance metrics export
- **Grafana**: Dashboard integration for application metrics

### SIEM Integration
- **Elastic Security**: Protocol events as security logs
- **Splunk**: Application transaction analysis
- **Sumo Logic**: Performance and error correlation

### Development Tools
- **OpenAPI/Swagger**: API specification correlation
- **Postman**: API testing result correlation
- **Load Testing Tools**: Performance baseline comparison

## Success Metrics

### Functional Metrics
- **Protocol Coverage**: >95% accurate parsing for supported protocols
- **Correlation Accuracy**: >90% correct request/response pairing
- **Transaction Reconstruction**: >85% complete application flows
- **Error Detection**: >99% capture of application-layer errors

### Performance Metrics
- **Processing Speed**: 1M HTTP transactions/second parsing capability
- **Memory Efficiency**: <1KB memory per tracked session
- **CPU Overhead**: <10% additional CPU for protocol parsing
- **Real-time Capability**: <1s latency for live protocol analysis

### Business Impact Metrics
- **Debug Time Reduction**: 60% faster application issue resolution
- **Error Correlation**: 75% improvement in root cause identification
- **Service Dependency Mapping**: Automated service topology discovery
- **Performance Optimization**: 40% improvement in application performance insights

## Future Enhancements

### Advanced Protocol Support
- **HTTP/3 (QUIC)**: Next-generation HTTP protocol
- **GraphQL**: Query-level analysis and optimization
- **WebRTC**: Real-time communication protocol analysis
- **Custom Protocols**: Framework for proprietary protocol parsers

### Machine Learning Integration
- **Anomaly Detection**: ML-based detection of unusual protocol patterns
- **Performance Prediction**: Predictive analysis of application performance
- **Security Analysis**: Behavioral analysis for threat detection
- **Auto-correlation**: ML-assisted protocol correlation

### Cloud-Native Features
- **Kubernetes Integration**: Pod and service correlation
- **Serverless Support**: Lambda and function-as-a-service analysis
- **Cloud Provider Integration**: AWS, GCP, Azure native integration
- **Container Runtime Analysis**: Docker, containerd protocol awareness