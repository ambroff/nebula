#include "nebula/interface.hpp"
#include "nebula/header.hpp"
#include <cstring>

// Define IP header structure for parsing
struct iphdr {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

namespace nebula {

// Process packet from UDP going to TUN device
void Interface::handle_outside_packet(const uint8_t* data, size_t len, const Endpoint& from) {
    // Minimum packet size check
    if (len < HEADER_SIZE) {
        // TODO: Log error - packet too small
        return;
    }
    
    // Update statistics
    rx_packets_.fetch_add(1, std::memory_order_relaxed);
    rx_bytes_.fetch_add(len, std::memory_order_relaxed);
    
    // Parse header
    Header header;
    auto header_result = header.decode(data);
    if (header_result.is_error()) {
        // TODO: Log error - invalid header
        return;
    }
    
    // Route based on message type
    const uint8_t* payload = data + HEADER_SIZE;
    size_t payload_len = len - HEADER_SIZE;
    
    switch (header.type) {
        case MessageType::Message:
            process_message_packet(header, payload, payload_len, from);
            break;
            
        case MessageType::Handshake:
            process_handshake_packet(header, payload, payload_len, from);
            break;
            
        case MessageType::Test:
            process_test_packet(header, payload, payload_len, from);
            break;
            
        case MessageType::CloseTunnel:
            process_close_tunnel_packet(header, payload, payload_len, from);
            break;
            
        default:
            // TODO: Log unknown message type
            break;
    }
}

// Process regular encrypted data packet
void Interface::process_message_packet(const Header& header, const uint8_t* data, 
                                     size_t len, const Endpoint& from) {
    // Look up connection by remote index
    auto host_info = host_map_->query_reverse_index(header.remote_index);
    if (!host_info) {
        // TODO: Log - no host found for remote index
        return;
    }
    
    // Verify we have a connection state
    if (!host_info->connection_state()) {
        // TODO: Log - no connection state
        return;
    }
    
    // Update remote endpoint (learn new address for roaming support)
    host_info->remotes().learn_remote(from);
    
    // Update statistics
    host_info->rx_packets.fetch_add(1, std::memory_order_relaxed);
    host_info->rx_bytes.fetch_add(len, std::memory_order_relaxed);
    
    // Decrypt the payload
    std::array<uint8_t, HEADER_SIZE> header_bytes;
    header.encode(header_bytes.data());
    
    auto decrypted = host_info->connection_state()->decrypt(
        data, len,
        header_bytes.data(), header_bytes.size(),
        header.message_counter
    );
    
    if (decrypted.is_error()) {
        // TODO: Log decryption error
        return;
    }
    
    // Parse inner IP packet to get source/dest for firewall
    if (decrypted.value().size() < 20) {  // Minimum IP header size
        // TODO: Log - packet too small
        return;
    }
    
    // Extract IP header info
    const auto* ip_header = reinterpret_cast<const struct iphdr*>(decrypted.value().data());
    VpnIp src_ip = ntohl(ip_header->saddr);
    VpnIp dst_ip = ntohl(ip_header->daddr);
    uint8_t protocol = ip_header->protocol;
    
    // Check inbound firewall rules
    if (firewall_) {
        auto result = firewall_->check_inbound(src_ip, dst_ip,
                                              decrypted.value().data(), 
                                              decrypted.value().size(),
                                              protocol, host_info->cert());
        if (!result.allowed) {
            // TODO: Log dropped packet
            return;
        }
    }
    
    // Write to TUN device
    if (tun_) {
        auto write_result = tun_->write(decrypted.value().data(), decrypted.value().size());
        if (write_result.is_error()) {
            // TODO: Log write error
        }
    }
}

// Process handshake packet
void Interface::process_handshake_packet(const Header& header, const uint8_t* data,
                                       size_t len, const Endpoint& from) {
    // TODO: Implement handshake processing
    // This will involve:
    // 1. Looking up or creating HostInfo
    // 2. Processing Noise handshake message
    // 3. Establishing connection state when complete
    // 4. Sending response if needed
}

// Process test packet (ping/pong)
void Interface::process_test_packet(const Header& header, const uint8_t* data,
                                  size_t len, const Endpoint& from) {
    if (header.subtype == MessageSubType::TestRequest) {
        // Echo back as TestReply
        Header reply_header = header;
        reply_header.subtype = MessageSubType::TestReply;
        
        // Build response packet
        std::vector<uint8_t> response(HEADER_SIZE + len);
        reply_header.encode(response.data());
        if (len > 0) {
            std::memcpy(response.data() + HEADER_SIZE, data, len);
        }
        
        // Send response
        udp_->send(response.data(), response.size(), from);
    }
    // TestReply packets are just logged/ignored
}

// Process tunnel close packet
void Interface::process_close_tunnel_packet(const Header& header, const uint8_t* data,
                                          size_t len, const Endpoint& from) {
    // Look up connection
    auto host_info = host_map_->query_reverse_index(header.remote_index);
    if (!host_info) {
        return;
    }
    
    // Remove the connection
    host_map_->delete_host_info(host_info);
    
    // TODO: Log tunnel closure
}

} // namespace nebula