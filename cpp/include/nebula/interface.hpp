#pragma once

#include "types.hpp"
#include "config.hpp"
#include "hostmap.hpp"
#include "tun.hpp"
#include "udp.hpp"
#include "firewall.hpp"
#include "cert.hpp"
#include "header.hpp"
#include <memory>
#include <thread>
#include <atomic>
#include <boost/asio/io_context.hpp>

namespace nebula {

// Forward declarations
class HandshakeManager;

// Main interface coordinating all Nebula components
class Interface {
public:
    Interface(std::shared_ptr<Config> config);
    ~Interface();
    
    // Initialize all components
    Result<void> initialize();
    
    // Start the interface (begin packet processing)
    Result<void> start();
    
    // Stop the interface gracefully
    void stop();
    
    // Check if interface is running
    bool is_running() const { return running_.load(); }
    
    // Get components
    HostMap& host_map() { return *host_map_; }
    const HostMap& host_map() const { return *host_map_; }
    
    // Packet processing (called by TUN/UDP threads)
    void consume_inside_packet(const uint8_t* data, size_t len, const PacketInfo& info);
    void handle_outside_packet(const uint8_t* data, size_t len, const Endpoint& from);
    
private:
    // Component initialization
    Result<void> initialize_pki();
    Result<void> initialize_tun();
    Result<void> initialize_udp();
    Result<void> initialize_firewall();
    
    // Thread functions
    void listen_tun();
    void listen_udp();
    
    // Packet processing helpers
    void process_message_packet(const Header& header, const uint8_t* data, size_t len, const Endpoint& from);
    void process_handshake_packet(const Header& header, const uint8_t* data, size_t len, const Endpoint& from);
    void process_test_packet(const Header& header, const uint8_t* data, size_t len, const Endpoint& from);
    void process_close_tunnel_packet(const Header& header, const uint8_t* data, size_t len, const Endpoint& from);
    
    // Send encrypted packet
    Result<void> send_message(HostInfo::Ptr host_info, const uint8_t* data, size_t len);
    
    // Initiate handshake if needed
    void initiate_handshake(VpnIp vpn_ip);
    
private:
    // Configuration
    std::shared_ptr<Config> config_;
    
    // Core components
    std::unique_ptr<HostMap> host_map_;
    std::unique_ptr<TunDevice> tun_;
    std::unique_ptr<UDPSocket> udp_;
    std::unique_ptr<Firewall> firewall_;
    std::unique_ptr<HandshakeManager> handshake_manager_;
    
    // PKI
    std::shared_ptr<Certificate> my_cert_;
    std::shared_ptr<PrivateKey> my_key_;
    std::shared_ptr<CAPool> ca_pool_;
    
    // IO contexts for async operations
    boost::asio::io_context tun_io_context_;
    boost::asio::io_context udp_io_context_;
    
    // Worker threads
    std::vector<std::thread> tun_threads_;
    std::vector<std::thread> udp_threads_;
    
    // State
    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};
    
    // Statistics
    std::atomic<uint64_t> tx_packets_{0};
    std::atomic<uint64_t> rx_packets_{0};
    std::atomic<uint64_t> tx_bytes_{0};
    std::atomic<uint64_t> rx_bytes_{0};
    std::atomic<uint64_t> handshake_count_{0};
};

// Packet info passed from TUN device
struct PacketInfo {
    VpnIp src_ip;
    VpnIp dst_ip;
    uint8_t protocol;
    bool is_multicast;
    bool is_broadcast;
};

} // namespace nebula