#pragma once

#include "types.hpp"
#include "cert.hpp"
#include <memory>
#include <string>
#include <vector>

namespace nebula {

// Firewall rule result
struct FirewallResult {
    bool allowed;
    std::string reason;  // For logging
};

// Basic firewall interface (placeholder for now)
class Firewall {
public:
    virtual ~Firewall() = default;
    
    // Check outbound traffic (from TUN to UDP)
    virtual FirewallResult check_outbound(
        VpnIp src_ip, VpnIp dst_ip,
        const uint8_t* packet, size_t len,
        uint8_t protocol) = 0;
    
    // Check inbound traffic (from UDP to TUN)
    virtual FirewallResult check_inbound(
        VpnIp src_ip, VpnIp dst_ip,
        const uint8_t* packet, size_t len,
        uint8_t protocol,
        std::shared_ptr<Certificate> peer_cert) = 0;
};

// Placeholder implementation that allows all traffic
class AllowAllFirewall : public Firewall {
public:
    FirewallResult check_outbound(
        VpnIp src_ip, VpnIp dst_ip,
        const uint8_t* packet, size_t len,
        uint8_t protocol) override {
        return {true, "allow-all"};
    }
    
    FirewallResult check_inbound(
        VpnIp src_ip, VpnIp dst_ip,
        const uint8_t* packet, size_t len,
        uint8_t protocol,
        std::shared_ptr<Certificate> peer_cert) override {
        return {true, "allow-all"};
    }
};

} // namespace nebula