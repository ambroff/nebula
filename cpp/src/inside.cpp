#include "nebula/interface.hpp"
#include "nebula/header.hpp"
#include <cstring>
#include <arpa/inet.h>

namespace nebula {

// Process packet from TUN device going out to UDP
void Interface::consume_inside_packet(const uint8_t* data, size_t len, const PacketInfo& info) {
    // Update statistics
    tx_packets_.fetch_add(1, std::memory_order_relaxed);
    tx_bytes_.fetch_add(len, std::memory_order_relaxed);
    
    // Drop local broadcast/multicast if configured
    if ((info.is_broadcast || info.is_multicast) && config_->drop_local_broadcast) {
        return;
    }
    
    // Check outbound firewall rules
    if (firewall_) {
        auto result = firewall_->check_outbound(info.src_ip, info.dst_ip, 
                                               data, len, info.protocol);
        if (!result.allowed) {
            // TODO: Log dropped packet
            return;
        }
    }
    
    // Determine destination - check for routed traffic
    VpnIp target_ip = info.dst_ip;
    
    // Check unsafe routes
    for (const auto& route : config_->tun.unsafe_routes) {
        if (route.network.contains(info.dst_ip)) {
            target_ip = route.via;
            break;
        }
    }
    
    // Look up host info
    auto host_info = host_map_->query_vpn_addr(target_ip);
    if (!host_info) {
        // No existing connection - initiate handshake
        initiate_handshake(target_ip);
        
        // TODO: Cache packet for retransmission after handshake completes
        return;
    }
    
    // Check if we have an established connection
    if (!host_info->has_connection_state()) {
        // Handshake in progress - cache packet
        // TODO: Implement packet caching
        return;
    }
    
    // Send the encrypted packet
    auto result = send_message(host_info, data, len);
    if (result.is_error()) {
        // TODO: Log error
    }
}

// Send encrypted message through established tunnel
Result<void> Interface::send_message(HostInfo::Ptr host_info, const uint8_t* data, size_t len) {
    if (!host_info->connection_state()) {
        return Result<void>::error("No connection state");
    }
    
    // Get remote endpoint
    auto remote = host_info->remotes().get_best();
    if (!remote) {
        return Result<void>::error("No remote endpoint");
    }
    
    // Increment packet counter
    host_info->tx_packets.fetch_add(1, std::memory_order_relaxed);
    host_info->tx_bytes.fetch_add(len, std::memory_order_relaxed);
    
    // Build header
    Header header;
    header.version = HEADER_VERSION;
    header.type = MessageType::Message;
    header.subtype = MessageSubType::MessageNone;
    header.reserved = 0;
    header.remote_index = host_info->remote_index();
    header.message_counter = host_info->tx_packets.load(std::memory_order_relaxed);
    
    // Serialize header
    std::array<uint8_t, HEADER_SIZE> header_bytes;
    header.encode(header_bytes.data());
    
    // Encrypt the payload with header as associated data
    auto encrypted = host_info->connection_state()->encrypt(
        data, len,
        header_bytes.data(), header_bytes.size(),
        header.message_counter
    );
    
    if (encrypted.is_error()) {
        return Result<void>::error("Encryption failed: " + encrypted.error());
    }
    
    // Build final packet: header + encrypted payload
    std::vector<uint8_t> packet(HEADER_SIZE + encrypted.value().size());
    std::memcpy(packet.data(), header_bytes.data(), HEADER_SIZE);
    std::memcpy(packet.data() + HEADER_SIZE, encrypted.value().data(), encrypted.value().size());
    
    // Send via UDP
    udp_->send(packet.data(), packet.size(), *remote);
    
    return Result<void>();
}

// Initiate handshake with a peer
void Interface::initiate_handshake(VpnIp vpn_ip) {
    // Check if we already have a pending handshake
    auto existing = host_map_->query_vpn_addr(vpn_ip);
    if (existing && !existing->has_connection_state()) {
        // Handshake already in progress
        return;
    }
    
    // Create new HostInfo for this connection
    static std::atomic<LocalIndex> next_index{1};
    LocalIndex local_index = next_index.fetch_add(1, std::memory_order_relaxed);
    
    auto host_info = std::make_shared<HostInfo>(vpn_ip, local_index);
    
    // Add to host map
    host_map_->add_host_info(host_info);
    
    // Update statistics
    handshake_count_.fetch_add(1, std::memory_order_relaxed);
    
    // TODO: Actually initiate the handshake using HandshakeManager
    // For now, this is a placeholder
}

} // namespace nebula