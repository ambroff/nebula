#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <chrono>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/network_v4.hpp>
#include <boost/asio/ip/network_v6.hpp>
#include <boost/asio/ip/udp.hpp>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

namespace nebula {

// Basic type aliases
using VpnIp = uint32_t;  // IPv4 address in network byte order
using LocalIndex = uint32_t;
using RemoteIndex = uint32_t;
using MessageCounter = uint64_t;

// Time types
using Duration = std::chrono::steady_clock::duration;
using TimePoint = std::chrono::steady_clock::time_point;

// Network types
using IpAddr = boost::asio::ip::address;
using IpAddrV4 = boost::asio::ip::address_v4;
using IpAddrV6 = boost::asio::ip::address_v6;
using Endpoint = boost::asio::ip::udp::endpoint;

// Certificate types
using CertFingerprint = std::array<uint8_t, 32>;  // SHA-256 hash

// Constants
constexpr uint32_t MTU = 9001;
constexpr uint32_t DEFAULT_MTU = 1300;
constexpr uint32_t MIN_MTU = 576;

// Convert VpnIp to string
inline std::string vpn_ip_to_string(VpnIp ip) {
    return IpAddrV4(ntohl(ip)).to_string();
}

// Convert string to VpnIp
inline VpnIp string_to_vpn_ip(const std::string& str) {
    return htonl(IpAddrV4::from_string(str).to_uint());
}

// IP network representation
struct IpNet {
    VpnIp ip;
    uint8_t prefix_length;
    
    IpNet() : ip(0), prefix_length(0) {}
    IpNet(VpnIp addr, uint8_t prefix) : ip(addr), prefix_length(prefix) {}
    
    // Create from CIDR string (e.g., "192.168.1.0/24")
    static IpNet from_string(const std::string& cidr);
    
    // Convert to string
    std::string to_string() const;
    
    // Check if an IP is within this network
    bool contains(VpnIp addr) const;
    
    // Get network mask
    VpnIp mask() const;
    
    // Get network address (with host bits zeroed)
    VpnIp network() const;
};

// Represents a route in the routing table
struct Route {
    IpNet network;
    VpnIp via;  // Next hop, 0 for direct routes
    uint32_t metric;
    
    Route() : via(0), metric(0) {}
    Route(const IpNet& net, VpnIp nexthop = 0, uint32_t m = 0) 
        : network(net), via(nexthop), metric(m) {}
};

// Result type for error handling
template<typename T>
class Result {
public:
    Result(T value) : value_(std::move(value)), has_value_(true) {}
    Result(std::string error) : error_(std::move(error)), has_value_(false) {}
    
    bool ok() const { return has_value_; }
    bool is_error() const { return !has_value_; }
    
    const T& value() const {
        if (!has_value_) {
            throw std::runtime_error("Result has no value: " + error_);
        }
        return value_;
    }
    
    T& value() {
        if (!has_value_) {
            throw std::runtime_error("Result has no value: " + error_);
        }
        return value_;
    }
    
    const std::string& error() const {
        if (has_value_) {
            throw std::runtime_error("Result has no error");
        }
        return error_;
    }
    
private:
    T value_;
    std::string error_;
    bool has_value_;
};

// Specialization for void
template<>
class Result<void> {
public:
    Result() : has_value_(true) {}
    Result(std::string error) : error_(std::move(error)), has_value_(false) {}
    
    bool ok() const { return has_value_; }
    bool is_error() const { return !has_value_; }
    
    const std::string& error() const {
        if (has_value_) {
            throw std::runtime_error("Result has no error");
        }
        return error_;
    }
    
private:
    std::string error_;
    bool has_value_;
};

// Buffer type for packet data
using Buffer = std::vector<uint8_t>;

// Fixed-size buffer for stack allocation
template<size_t N>
using FixedBuffer = std::array<uint8_t, N>;

} // namespace nebula