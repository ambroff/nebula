# Nebula C++ Port Plan

## Overview
This document outlines the plan to port a minimal subset of Nebula to C++ using primarily Boost libraries (Boost.Asio for networking, Boost.Json for configuration) with OpenSSL for cryptography. The port will exclude lighthouse functionality, certificate generation, SSH server, and DNS server.

**Last Updated**: July 2025
**Status**: In Progress (Phase 3)

## Architecture Overview

### Core Components to Port

1. **Packet Processing Pipeline**
   - Header parsing and serialization (16-byte header format)
   - Message type routing (handshake, message, test, close tunnel)
   - Inside handler (TUN → UDP flow)
   - Outside handler (UDP → TUN flow)

2. **Connection Management**
   - HostMap for tracking peer connections
   - ConnectionState for Noise protocol state
   - Remote endpoint tracking and mobility

3. **Cryptography**
   - Noise IX protocol implementation
   - AES-256-GCM and ChaCha20-Poly1305 support
   - Curve25519 and P256 ECDH
   - Certificate parsing (v1 protobuf, v2 ASN.1)

4. **Network Layer**
   - TUN device abstraction (Linux, macOS, Windows)
   - UDP socket with Boost.Asio
   - UDP hole punching

5. **Security**
   - Firewall with group-based rules
   - Stateful connection tracking
   - Certificate validation

### Excluded Components
- Lighthouse discovery service
- Certificate generation (nebula-cert tool)
- SSH server functionality
- DNS server functionality
- Relay functionality
- Control protocol

## Directory Structure
```
cpp/
├── include/nebula/
│   ├── types.hpp              # Common types and constants
│   ├── header.hpp             # Packet header structures
│   ├── interface.hpp          # Main orchestrator class
│   ├── hostmap.hpp            # Connection tracking
│   ├── connection_state.hpp   # Noise protocol state
│   ├── handshake.hpp          # Handshake management
│   ├── firewall.hpp           # Packet filtering
│   ├── cert.hpp               # Certificate parsing/validation
│   ├── tun.hpp                # TUN device abstraction
│   ├── udp.hpp                # UDP socket abstraction
│   ├── config.hpp             # Configuration management
│   └── crypto.hpp             # Crypto primitives wrapper
├── src/
│   ├── interface.cpp
│   ├── hostmap.cpp
│   ├── connection_state.cpp
│   ├── handshake.cpp
│   ├── firewall.cpp
│   ├── cert/
│   │   ├── cert_v1.cpp        # Protobuf cert support
│   │   └── cert_v2.cpp        # ASN.1 cert support
│   ├── tun/
│   │   ├── tun_linux.cpp
│   │   ├── tun_darwin.cpp
│   │   └── tun_windows.cpp
│   ├── inside.cpp             # TUN→UDP packet flow
│   ├── outside.cpp            # UDP→TUN packet flow
│   └── main.cpp
├── proto/                      # Certificate protobuf definitions
│   └── cert_v1.proto
├── examples/
│   └── config.json            # Example configuration
├── tests/
├── CMakeLists.txt
└── Makefile
```

## Key Data Structures

### Packet Header Format
```cpp
struct Header {
    uint8_t version;      // 4 bits version, 4 bits type
    uint8_t subtype;      // Message subtype
    uint16_t reserved;    // Reserved for future use
    uint32_t remoteIndex; // Connection index
    uint64_t messageCounter; // Replay protection
};
```

### Message Types
- `handshake` (type 0): Noise protocol handshake messages
- `message` (type 1): Encrypted data packets
- `recvError` (type 2): Error notifications
- `test` (type 4): Ping/pong messages
- `closeTunnel` (type 5): Connection teardown

### Core Classes

1. **Interface**: Main orchestrator coordinating all components
2. **HostMap**: Thread-safe map of VPN IPs to HostInfo structures
3. **HostInfo**: Per-peer connection state including:
   - Noise protocol state
   - Remote endpoints
   - Connection statistics
   - Handshake state
4. **ConnectionState**: Noise IX protocol state machine
5. **Firewall**: Rule evaluation engine with stateful tracking
6. **TunDevice**: Platform-specific TUN device implementation
7. **UDPSocket**: Boost.Asio-based UDP networking

## Configuration Format

Using Boost.Json for a simplified configuration format (updated from original Boost.PropertyTree plan):

```json
{
  "pki": {
    "ca": "ca.crt",
    "cert": "host.crt",
    "key": "host.key",
    "blocklist": ["fingerprint1", "fingerprint2"]
  },
  "static_host_map": {
    "192.168.100.1": ["1.2.3.4:4242", "1.2.3.5:4242"]
  },
  "listen": {
    "host": "0.0.0.0",
    "port": 4242,
    "batch": 64
  },
  "tun": {
    "dev": "nebula1",
    "mtu": 1300,
    "routes": [
      {"network": "10.0.0.0/8", "metric": 100}
    ],
    "unsafe_routes": [
      {"network": "172.16.0.0/12", "via": "192.168.100.5"}
    ]
  },
  "firewall": {
    "conntrack": {
      "tcp_timeout": 12000,
      "udp_timeout": 60,
      "default_timeout": 60
    },
    "outbound": [
      {"port": "any", "proto": "any", "host": "any"}
    ],
    "inbound": [
      {"port": 22, "proto": "tcp", "groups": ["admin", "ssh"]},
      {"port": 443, "proto": "tcp", "cidr": "10.0.0.0/8"}
    ]
  },
  "punchy": {
    "punch": true,
    "respond": true,
    "delay": "1s",
    "interval": "1m"
  },
  "cipher": "aes",
  "logging": {
    "level": "info",
    "format": "json"
  }
}
```

## Implementation Phases

### Phase 1: Core Infrastructure (Week 1-2)
1. **Basic Types and Headers**
   - Define common types (VpnIp, IPNet, etc.)
   - Implement packet header serialization
   - Port message type constants

2. **Configuration System**
   - JSON schema design
   - Config loader using Boost.Json
   - Validation and defaults

3. **Platform Abstractions**
   - TUN device interface
   - Platform-specific implementations
   - Basic logging framework

### Phase 2: Cryptography (Week 2-3)
1. **Crypto Primitives**
   - OpenSSL wrapper for ciphers
   - Key operations (Curve25519, P256)
   - Hash functions (SHA-256)

2. **Noise Protocol**
   - Port Noise IX implementation
   - Key derivation and management
   - Message encryption/decryption

3. **Certificate Handling**
   - Protobuf parsing for v1 certs
   - ASN.1 parsing for v2 certs
   - Signature verification
   - CA pool management

### Phase 3: Core Networking (Week 3-4)
1. **Connection Management**
   - Thread-safe HostMap
   - ConnectionState lifecycle
   - Endpoint management

2. **UDP Networking**
   - Boost.Asio UDP socket
   - Async send/receive
   - Multi-threading support

3. **Packet Flow**
   - Inside handler implementation
   - Outside handler implementation
   - Routing logic

### Phase 4: Security Features (Week 4-5)
1. **Firewall Engine**
   - Rule parsing and storage
   - Fast packet matching
   - Connection tracking

2. **Handshake Protocol**
   - Handshake manager
   - Retry logic
   - Timeout handling

3. **UDP Hole Punching**
   - Punch packet generation
   - Response handling
   - Configurable intervals

### Phase 5: Integration and Testing (Week 5-6)
1. **System Integration**
   - Component wiring
   - Main application loop
   - Signal handling

2. **Testing Suite**
   - Unit tests for components
   - Integration tests
   - Compatibility tests with Go Nebula

## Technical Design Decisions

### Threading Model
- Boost.Asio io_context with thread pool
- Separate I/O contexts for TUN and UDP
- Lock-free queues for packet passing
- Fine-grained locking for shared state

### Memory Management
- Smart pointers throughout (shared_ptr, unique_ptr)
- Buffer pools for packet data
- RAII for all resources
- No raw new/delete

### Error Handling
- Result<T> type for fallible operations
- Exceptions only for truly exceptional cases
- Structured logging with context

### Performance Optimizations
- Zero-copy packet processing where possible
- Batch UDP operations
- Connection cache for firewall
- Vectored I/O for TUN devices

## Dependencies

### Required
- **Boost** (>= 1.75)
  - Asio (networking)
  - System (error handling)
  - Thread (threading)
  - Json (configuration)
- **OpenSSL** (>= 1.1.1)
  - EVP API for ciphers
  - EC operations
  - X509 handling
- **Protobuf** (>= 3.0)
  - For v1 certificate format

### Optional
- **spdlog**: Structured logging
- **Google Test**: Unit testing
- **benchmark**: Micro-benchmarks

## Build System

Using GNU Make with automatic dependency tracking:

```makefile
# Compiler settings
CXX := g++
CXXFLAGS := -std=c++20 -Wall -Wextra -O2 -g -pthread
LDFLAGS := -pthread

# Feature detection
HAVE_BOOST := $(shell pkg-config --exists boost && echo 1)
HAVE_OPENSSL := $(shell pkg-config --exists openssl && echo 1)
HAVE_PROTOBUF := $(shell pkg-config --exists protobuf && echo 1)

# Include paths
CXXFLAGS += $(shell pkg-config --cflags boost openssl protobuf)
LDFLAGS += $(shell pkg-config --libs boost openssl protobuf)

# Platform detection
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    PLATFORM_SOURCES := src/tun/tun_linux.cpp
    CXXFLAGS += -DPLATFORM_LINUX
endif
ifeq ($(UNAME_S),Darwin)
    PLATFORM_SOURCES := src/tun/tun_darwin.cpp
    CXXFLAGS += -DPLATFORM_DARWIN
endif

# Source files
SOURCES := $(wildcard src/*.cpp) $(wildcard src/cert/*.cpp) $(PLATFORM_SOURCES)
OBJECTS := $(SOURCES:src/%.cpp=build/%.o)

# Targets
all: nebula

nebula: $(OBJECTS)
	$(CXX) $(LDFLAGS) -o $@ $^

build/%.o: src/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -Iinclude -c -o $@ $<

clean:
	rm -rf build/ nebula

.PHONY: all clean
```

## Testing Strategy

### Unit Tests
- Test each component in isolation
- Mock dependencies where needed
- Focus on edge cases and error conditions

### Integration Tests
- Test component interactions
- Verify packet flow end-to-end
- Test configuration loading

### Compatibility Tests
- Ensure interoperability with Go Nebula
- Test all supported cipher suites
- Verify certificate formats

### Performance Tests
- Throughput benchmarks
- Latency measurements
- Connection scaling tests

## Milestones

1. **Milestone 1**: Basic packet processing
   - Can parse and generate Nebula packets
   - Configuration loading works
   - TUN device can be opened

2. **Milestone 2**: Cryptographic operations
   - Can perform Noise handshakes
   - Certificate validation works
   - Packet encryption/decryption functional

3. **Milestone 3**: Basic connectivity
   - Can establish connection with Go Nebula
   - Bidirectional traffic flow
   - Basic firewall rules work

4. **Milestone 4**: Full functionality
   - All features working
   - Performance acceptable
   - Tests passing

## Success Criteria

- Establishes encrypted tunnels with Go Nebula peers
- Passes bidirectional traffic correctly
- Respects firewall rules and groups
- Handles connection mobility
- Performance within 20% of Go implementation
- Clean code with good test coverage

## Implementation Progress

### Completed Components ✓
1. **Basic Types and Headers** (types.hpp, header.hpp)
   - VpnIp conversions and IpNet CIDR support
   - 16-byte packet header encoding/decoding
   - Result<T> error handling with template specializations

2. **Configuration System** (config.hpp)
   - JSON-based configuration using Boost.Json
   - Schema validation and default values
   - Example configuration file

3. **Platform Abstractions** (tun.hpp, tun_linux.cpp)
   - TUN device interface definition
   - Linux implementation with ioctl operations
   - Placeholder for macOS/Windows support

4. **UDP Socket Wrapper** (udp.hpp)
   - Boost.Asio-based async UDP implementation
   - Statistics tracking with atomic counters
   - Configurable batch processing

5. **Crypto Primitives** (crypto.hpp)
   - OpenSSL EVP API wrappers
   - Curve25519 and P256 key operations
   - AES-256-GCM and ChaCha20-Poly1305 AEAD
   - SHA256 hashing

6. **Noise Protocol** (noise.hpp)
   - Complete Noise_IX implementation
   - Handshake state machine
   - Transport key derivation

7. **Certificate Parsing** (cert.hpp, cert_v1.cpp)
   - Protobuf-based v1 certificate support
   - PEM encoding/decoding
   - Certificate validation and CA pool management
   - Signature verification with Ed25519

8. **Build System** (Makefile)
   - Automatic dependency tracking
   - Platform detection (Linux/macOS)
   - Protobuf generation rules
   - Debug/release build targets

9. **Test Suite** (main.cpp)
   - Component integration tests
   - Demonstrates all implemented features
   - Validates core functionality

### TODO List - Remaining Work

#### Phase 3: Core Networking (In Progress)
- [ ] **HostMap and ConnectionState** (Priority: High)
  - Thread-safe map of VPN IPs to HostInfo
  - Connection state lifecycle management
  - Remote endpoint tracking
  - Connection statistics

- [ ] **Packet Flow Handlers** (Priority: High)
  - Inside handler (TUN → UDP)
  - Outside handler (UDP → TUN)
  - Message type routing
  - Packet encapsulation/decapsulation

#### Phase 4: Security Features
- [ ] **Firewall Engine** (Priority: Medium)
  - Rule parsing from configuration
  - Fast packet matching algorithm
  - Connection tracking state
  - Group-based access control

- [ ] **Handshake Manager** (Priority: Medium)
  - Handshake initiation and response
  - Retry logic with exponential backoff
  - Timeout handling
  - Connection establishment

- [ ] **UDP Hole Punching** (Priority: Low)
  - Punch packet generation
  - Response handling
  - Configurable intervals

#### Phase 5: Integration and Polish
- [ ] **Main Application** (Priority: High)
  - Component wiring and initialization
  - Main event loop with signal handling
  - Graceful shutdown
  - Command-line argument parsing

- [ ] **Logging Framework** (Priority: Low)
  - Structured logging with levels
  - JSON output format option
  - Performance-conscious design

- [ ] **Performance Optimizations** (Priority: Low)
  - Buffer pools for packet data
  - Zero-copy packet processing
  - Vectored I/O for TUN devices
  - Connection cache for firewall

- [ ] **Additional Platform Support** (Priority: Low)
  - macOS TUN implementation (tun_darwin.cpp)
  - Windows TUN implementation (tun_windows.cpp)
  - FreeBSD support

### Technical Decisions Made During Implementation

1. **C++20 Standard**: Upgraded from C++17 for better concepts and coroutines support
2. **Boost.Json over PropertyTree**: Better performance and cleaner API for JSON parsing
3. **EVP API for OpenSSL**: Using modern EVP API instead of deprecated direct functions
4. **Atomic Counters**: Using std::atomic for thread-safe statistics without mutex overhead
5. **Template Specialization**: Result<std::string> specialization to avoid constructor ambiguity
6. **GNU Make**: Chosen over CMake for simpler dependency management in this project

### Known Issues and Limitations

1. **Platform Support**: Currently only Linux TUN device is implemented
2. **Certificate v2**: ASN.1 certificate format not yet implemented
3. **Cipher Selection**: Only AES-256-GCM implemented, ChaCha20-Poly1305 pending
4. **IPv6 Support**: Current implementation focuses on IPv4 only
5. **Connection Mobility**: Endpoint updates not yet implemented

### Next Steps

1. Implement HostMap and ConnectionState for connection management
2. Create packet flow handlers to enable actual VPN functionality
3. Port firewall engine for security policy enforcement
4. Wire everything together in main application
5. Add compatibility testing with Go Nebula nodes