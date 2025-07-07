.PHONY: build test clean run-test install

# Binary name
BINARY_NAME=janus
BINARY_PATH=bin/$(BINARY_NAME)

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOCLEAN=$(GOCMD) clean
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build the project
build:
	mkdir -p bin
	$(GOBUILD) -o $(BINARY_PATH) -v ./cmd/janus

# Run tests
test:
	$(GOTEST) -v ./...

# Run tests with coverage
test-coverage:
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
clean:
	$(GOCLEAN)
	rm -rf bin/
	rm -f coverage.out coverage.html

# Download dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Install the binary to $GOPATH/bin
install: build
	$(GOCMD) install ./cmd/janus

# Run a quick test with example PCAP files
run-example:
	@echo "Note: You need to provide your own PCAP files for testing"
	@echo "Example usage:"
	@echo "  ./$(BINARY_PATH) -pcap1 capture1.pcap -pcap2 capture2.pcap -point1 container -point2 host"

# Lint the code (requires golangci-lint)
lint:
	@which golangci-lint > /dev/null || (echo "golangci-lint not found. Install from https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run

# Format code
fmt:
	$(GOCMD) fmt ./...

# Check for security issues (requires gosec)
security:
	@which gosec > /dev/null || (echo "gosec not found. Install with: go install github.com/securego/gosec/v2/cmd/gosec@latest" && exit 1)
	gosec ./...

# All checks before committing
check: fmt test lint

# Help
help:
	@echo "Available targets:"
	@echo "  build         - Build the janus binary"
	@echo "  test          - Run all tests"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  clean         - Remove build artifacts"
	@echo "  deps          - Download and tidy dependencies"
	@echo "  install       - Install janus to GOPATH/bin"
	@echo "  fmt           - Format code"
	@echo "  lint          - Run linter (requires golangci-lint)"
	@echo "  security      - Run security checks (requires gosec)"
	@echo "  check         - Run fmt, test, and lint"
	@echo "  help          - Show this help message"