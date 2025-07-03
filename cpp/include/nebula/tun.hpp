#pragma once

#include "types.hpp"
#include <memory>
#include <functional>
#include <string>
#include <vector>

namespace nebula {

// Forward declarations
class TunDevice;

// Callback for received packets from TUN
using TunPacketHandler = std::function<void(const uint8_t* data, size_t len)>;

// TUN device configuration
struct TunDeviceConfig {
    std::string name = "nebula1";      // Device name
    uint32_t mtu = DEFAULT_MTU;        // Maximum transmission unit
    std::vector<Route> routes;         // Routes to add
    std::vector<Route> unsafe_routes;  // Unsafe routes (via specific hosts)
    bool persist = false;              // Keep device after process exits
};

// Statistics for TUN device
struct TunStats {
    std::atomic<uint64_t> packets_sent{0};
    std::atomic<uint64_t> packets_received{0};
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_received{0};
    std::atomic<uint64_t> errors{0};
};

// Abstract base class for TUN device implementations
class TunDevice {
public:
    using Ptr = std::shared_ptr<TunDevice>;
    
    virtual ~TunDevice() = default;
    
    // Create platform-specific TUN device
    static Result<Ptr> create(const TunDeviceConfig& config);
    
    // Open the device
    virtual Result<void> open() = 0;
    
    // Close the device
    virtual void close() = 0;
    
    // Configure IP address and bring up interface
    virtual Result<void> configure(VpnIp ip, uint8_t prefix_len) = 0;
    
    // Add a route
    virtual Result<void> add_route(const Route& route) = 0;
    
    // Remove a route
    virtual Result<void> remove_route(const Route& route) = 0;
    
    // Read a packet (blocking)
    virtual Result<size_t> read(uint8_t* buffer, size_t max_len) = 0;
    
    // Write a packet
    virtual Result<void> write(const uint8_t* data, size_t len) = 0;
    
    // Start async reading (non-blocking)
    virtual Result<void> start_async_read(TunPacketHandler handler) = 0;
    
    // Stop async reading
    virtual void stop_async_read() = 0;
    
    // Get device name
    const std::string& name() const { return config_.name; }
    
    // Get MTU
    uint32_t mtu() const { return config_.mtu; }
    
    // Get statistics
    const TunStats& stats() const { return stats_; }
    
    // Check if device is open
    virtual bool is_open() const = 0;
    
    // Get file descriptor (for select/poll/epoll)
    virtual int fd() const = 0;
    
protected:
    TunDevice(const TunDeviceConfig& config) : config_(config) {}
    
    TunDeviceConfig config_;
    mutable TunStats stats_;
};

// Platform-specific implementations will be in separate files:
// - tun_linux.cpp
// - tun_darwin.cpp  
// - tun_windows.cpp

} // namespace nebula