#pragma once

#include "types.hpp"
#include "noise.hpp"
#include "cert.hpp"
#include <memory>
#include <unordered_map>
#include <shared_mutex>
#include <atomic>
#include <chrono>
#include <list>
#include <optional>

namespace nebula {

// Forward declarations
class HostInfo;
class RemoteList;
class HandshakePacket;

// Thread-safe remote endpoint list for a host
class RemoteList {
public:
    RemoteList();
    
    // Add or update a remote endpoint
    void learn_remote(const Endpoint& endpoint);
    
    // Get the current best remote endpoint
    std::optional<Endpoint> get_best() const;
    
    // Get all known remote endpoints
    std::vector<Endpoint> get_all() const;
    
    // Set the primary remote endpoint
    void set_primary(const Endpoint& endpoint);
    
    // Clear all remote endpoints
    void clear();
    
private:
    mutable std::shared_mutex mutex_;
    std::optional<Endpoint> primary_;
    std::list<Endpoint> remotes_;  // Most recent first
    static constexpr size_t max_remotes_ = 10;
};

// Cached handshake packet to prevent replay attacks
struct HandshakePacket {
    std::vector<uint8_t> data;
    RemoteIndex remote_index;
    MessageCounter counter;
    TimePoint timestamp;
};

// Information about a remote host
class HostInfo : public std::enable_shared_from_this<HostInfo> {
public:
    using Ptr = std::shared_ptr<HostInfo>;
    
    HostInfo(VpnIp vpn_ip, LocalIndex local_index);
    
    // Connection state management
    void set_connection_state(std::unique_ptr<ConnectionState> state);
    ConnectionState* connection_state() { return connection_state_.get(); }
    const ConnectionState* connection_state() const { return connection_state_.get(); }
    bool has_connection_state() const { return connection_state_ != nullptr; }
    
    // Remote endpoint management
    RemoteList& remotes() { return remotes_; }
    const RemoteList& remotes() const { return remotes_; }
    
    // Index getters
    VpnIp vpn_ip() const { return vpn_ip_; }
    LocalIndex local_index() const { return local_index_; }
    RemoteIndex remote_index() const { return remote_index_; }
    void set_remote_index(RemoteIndex idx) { remote_index_ = idx; }
    
    // VPN addresses (for hosts with multiple IPs)
    void add_vpn_addr(VpnIp addr);
    const std::vector<VpnIp>& vpn_addrs() const { return vpn_addrs_; }
    
    // Certificate information
    void set_cert(std::shared_ptr<Certificate> cert) { cert_ = cert; }
    std::shared_ptr<Certificate> cert() const { return cert_; }
    
    // Handshake packet caching
    void cache_handshake_packet(const HandshakePacket& packet);
    std::optional<HandshakePacket> get_cached_handshake() const;
    void clear_cached_handshake();
    
    // Timing information
    void update_last_handshake() { last_handshake_ = std::chrono::steady_clock::now(); }
    TimePoint last_handshake() const { return last_handshake_; }
    
    void update_last_roam() { last_roam_ = std::chrono::steady_clock::now(); }
    TimePoint last_roam() const { return last_roam_; }
    
    // Statistics
    std::atomic<uint64_t> tx_packets{0};
    std::atomic<uint64_t> rx_packets{0};
    std::atomic<uint64_t> tx_bytes{0};
    std::atomic<uint64_t> rx_bytes{0};
    
    // Linked list for multiple HostInfos per VPN IP
    Ptr next;
    std::weak_ptr<HostInfo> prev;
    
    // Check if this is the primary HostInfo for its VPN IPs
    bool is_primary() const { return is_primary_; }
    void set_primary(bool primary) { is_primary_ = primary; }
    
private:
    VpnIp vpn_ip_;  // Primary VPN IP
    std::vector<VpnIp> vpn_addrs_;  // All VPN IPs including primary
    LocalIndex local_index_;
    RemoteIndex remote_index_ = 0;
    
    std::unique_ptr<ConnectionState> connection_state_;
    RemoteList remotes_;
    std::shared_ptr<Certificate> cert_;
    
    std::optional<HandshakePacket> cached_handshake_;
    mutable std::mutex handshake_mutex_;
    
    TimePoint last_handshake_;
    TimePoint last_roam_;
    
    bool is_primary_ = false;
};

// Thread-safe map of hosts with multiple index types
class HostMap {
public:
    HostMap();
    
    // Add a new HostInfo
    void add_host_info(HostInfo::Ptr host_info);
    
    // Query methods
    HostInfo::Ptr query_vpn_addr(VpnIp vpn_ip) const;
    HostInfo::Ptr query_index(LocalIndex index) const;
    HostInfo::Ptr query_reverse_index(RemoteIndex index) const;
    
    // Get all HostInfos for a VPN IP (including non-primary)
    std::vector<HostInfo::Ptr> query_all_vpn_addr(VpnIp vpn_ip) const;
    
    // Make a HostInfo primary for its VPN addresses
    void make_primary(HostInfo::Ptr host_info);
    
    // Delete a HostInfo
    // Returns true if this was the last HostInfo for its VPN IPs
    bool delete_host_info(HostInfo::Ptr host_info);
    
    // Add remote index mapping
    void add_remote_index(RemoteIndex index, HostInfo::Ptr host_info);
    
    // Remove remote index mapping
    void remove_remote_index(RemoteIndex index);
    
    // Promote the best HostInfo for a VPN IP based on criteria
    void try_promote_best(VpnIp vpn_ip);
    
    // Get statistics
    size_t size() const;
    size_t index_count() const;
    size_t remote_index_count() const;
    
    // Clear all entries
    void clear();
    
private:
    // Internal unlocked methods (caller must hold lock)
    void unlocked_add_host_info(HostInfo::Ptr host_info);
    bool unlocked_delete_host_info(HostInfo::Ptr host_info);
    void unlocked_make_primary(HostInfo::Ptr host_info);
    void unlocked_promote_newest(VpnIp vpn_ip);
    
private:
    mutable std::shared_mutex mutex_;
    
    // Multiple indexes for efficient lookup
    std::unordered_map<VpnIp, HostInfo::Ptr> hosts_;  // Primary hosts by VPN IP
    std::unordered_map<LocalIndex, HostInfo::Ptr> indexes_;  // By local index
    std::unordered_map<RemoteIndex, HostInfo::Ptr> remote_indexes_;  // By remote index
    
    // Maximum number of HostInfos per VPN IP
    static constexpr size_t max_hosts_per_vpn_ip_ = 5;
};

} // namespace nebula