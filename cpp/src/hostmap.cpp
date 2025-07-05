#include "nebula/hostmap.hpp"
#include <algorithm>

namespace nebula {

// RemoteList implementation

RemoteList::RemoteList() = default;

void RemoteList::learn_remote(const Endpoint& endpoint) {
    std::unique_lock lock(mutex_);
    
    // Remove if already exists
    auto it = std::find(remotes_.begin(), remotes_.end(), endpoint);
    if (it != remotes_.end()) {
        remotes_.erase(it);
    }
    
    // Add to front (most recent)
    remotes_.push_front(endpoint);
    
    // Limit size
    while (remotes_.size() > max_remotes_) {
        remotes_.pop_back();
    }
}

std::optional<Endpoint> RemoteList::get_best() const {
    std::shared_lock lock(mutex_);
    
    if (primary_) {
        return primary_;
    }
    
    if (!remotes_.empty()) {
        return remotes_.front();
    }
    
    return std::nullopt;
}

std::vector<Endpoint> RemoteList::get_all() const {
    std::shared_lock lock(mutex_);
    return std::vector<Endpoint>(remotes_.begin(), remotes_.end());
}

void RemoteList::set_primary(const Endpoint& endpoint) {
    std::unique_lock lock(mutex_);
    primary_ = endpoint;
    learn_remote(endpoint);  // Also add to list
}

void RemoteList::clear() {
    std::unique_lock lock(mutex_);
    primary_.reset();
    remotes_.clear();
}

// HostInfo implementation

HostInfo::HostInfo(VpnIp vpn_ip, LocalIndex local_index)
    : vpn_ip_(vpn_ip)
    , local_index_(local_index)
    , last_handshake_(std::chrono::steady_clock::now())
    , last_roam_(std::chrono::steady_clock::now()) {
    vpn_addrs_.push_back(vpn_ip);
}

void HostInfo::set_connection_state(std::unique_ptr<ConnectionState> state) {
    connection_state_ = std::move(state);
}

void HostInfo::add_vpn_addr(VpnIp addr) {
    if (std::find(vpn_addrs_.begin(), vpn_addrs_.end(), addr) == vpn_addrs_.end()) {
        vpn_addrs_.push_back(addr);
    }
}

void HostInfo::cache_handshake_packet(const HandshakePacket& packet) {
    std::lock_guard lock(handshake_mutex_);
    cached_handshake_ = packet;
}

std::optional<HandshakePacket> HostInfo::get_cached_handshake() const {
    std::lock_guard lock(handshake_mutex_);
    return cached_handshake_;
}

void HostInfo::clear_cached_handshake() {
    std::lock_guard lock(handshake_mutex_);
    cached_handshake_.reset();
}

// HostMap implementation

HostMap::HostMap() = default;

void HostMap::add_host_info(HostInfo::Ptr host_info) {
    std::unique_lock lock(mutex_);
    unlocked_add_host_info(host_info);
}

void HostMap::unlocked_add_host_info(HostInfo::Ptr host_info) {
    // Add to index by local index
    indexes_[host_info->local_index()] = host_info;
    
    // Add to remote index if set
    if (host_info->remote_index() != 0) {
        remote_indexes_[host_info->remote_index()] = host_info;
    }
    
    // Handle VPN IP mapping
    auto primary = hosts_.find(host_info->vpn_ip());
    if (primary == hosts_.end()) {
        // First host for this VPN IP - make it primary
        hosts_[host_info->vpn_ip()] = host_info;
        host_info->set_primary(true);
    } else {
        // Add to linked list
        auto current = primary->second;
        size_t count = 1;
        
        // Find end of list and count
        while (current->next && count < max_hosts_per_vpn_ip_) {
            current = current->next;
            count++;
        }
        
        if (count < max_hosts_per_vpn_ip_) {
            // Add to end
            current->next = host_info;
            host_info->prev = current;
        } else {
            // Replace the last one
            if (current->prev.lock()) {
                current->prev.lock()->next = host_info;
            }
            host_info->prev = current->prev;
            
            // Clean up the old one
            indexes_.erase(current->local_index());
            if (current->remote_index() != 0) {
                remote_indexes_.erase(current->remote_index());
            }
        }
    }
    
    // Add mappings for additional VPN addresses
    for (auto vpn_addr : host_info->vpn_addrs()) {
        if (vpn_addr != host_info->vpn_ip() && hosts_.find(vpn_addr) == hosts_.end()) {
            hosts_[vpn_addr] = host_info;
        }
    }
}

HostInfo::Ptr HostMap::query_vpn_addr(VpnIp vpn_ip) const {
    std::shared_lock lock(mutex_);
    auto it = hosts_.find(vpn_ip);
    return (it != hosts_.end()) ? it->second : nullptr;
}

HostInfo::Ptr HostMap::query_index(LocalIndex index) const {
    std::shared_lock lock(mutex_);
    auto it = indexes_.find(index);
    return (it != indexes_.end()) ? it->second : nullptr;
}

HostInfo::Ptr HostMap::query_reverse_index(RemoteIndex index) const {
    std::shared_lock lock(mutex_);
    auto it = remote_indexes_.find(index);
    return (it != remote_indexes_.end()) ? it->second : nullptr;
}

std::vector<HostInfo::Ptr> HostMap::query_all_vpn_addr(VpnIp vpn_ip) const {
    std::shared_lock lock(mutex_);
    std::vector<HostInfo::Ptr> result;
    
    auto it = hosts_.find(vpn_ip);
    if (it != hosts_.end()) {
        auto current = it->second;
        while (current) {
            result.push_back(current);
            current = current->next;
        }
    }
    
    return result;
}

void HostMap::make_primary(HostInfo::Ptr host_info) {
    std::unique_lock lock(mutex_);
    unlocked_make_primary(host_info);
}

void HostMap::unlocked_make_primary(HostInfo::Ptr host_info) {
    // Find current primary
    auto it = hosts_.find(host_info->vpn_ip());
    if (it == hosts_.end() || it->second == host_info) {
        // Already primary or not in map
        return;
    }
    
    auto old_primary = it->second;
    
    // Remove host_info from linked list
    if (host_info->prev.lock()) {
        host_info->prev.lock()->next = host_info->next;
    }
    if (host_info->next) {
        host_info->next->prev = host_info->prev;
    }
    
    // Make host_info the new primary
    host_info->next = old_primary;
    host_info->prev.reset();
    old_primary->prev = host_info;
    
    // Update primary flags
    host_info->set_primary(true);
    old_primary->set_primary(false);
    
    // Update all VPN address mappings
    for (auto vpn_addr : host_info->vpn_addrs()) {
        hosts_[vpn_addr] = host_info;
    }
}

bool HostMap::delete_host_info(HostInfo::Ptr host_info) {
    std::unique_lock lock(mutex_);
    return unlocked_delete_host_info(host_info);
}

bool HostMap::unlocked_delete_host_info(HostInfo::Ptr host_info) {
    // Remove from indexes
    indexes_.erase(host_info->local_index());
    if (host_info->remote_index() != 0) {
        remote_indexes_.erase(host_info->remote_index());
    }
    
    // Handle linked list removal
    bool was_primary = host_info->is_primary();
    
    if (was_primary && host_info->next) {
        // Promote next to primary
        auto new_primary = host_info->next;
        new_primary->set_primary(true);
        new_primary->prev.reset();
        
        // Update all VPN address mappings
        for (auto vpn_addr : new_primary->vpn_addrs()) {
            hosts_[vpn_addr] = new_primary;
        }
    } else if (!was_primary) {
        // Remove from middle or end of list
        if (host_info->prev.lock()) {
            host_info->prev.lock()->next = host_info->next;
        }
        if (host_info->next) {
            host_info->next->prev = host_info->prev;
        }
    } else {
        // Was primary with no next - remove all VPN mappings
        for (auto vpn_addr : host_info->vpn_addrs()) {
            hosts_.erase(vpn_addr);
        }
        return true;  // Last host for these VPN IPs
    }
    
    return false;  // Not the last host
}

void HostMap::add_remote_index(RemoteIndex index, HostInfo::Ptr host_info) {
    std::unique_lock lock(mutex_);
    host_info->set_remote_index(index);
    remote_indexes_[index] = host_info;
}

void HostMap::remove_remote_index(RemoteIndex index) {
    std::unique_lock lock(mutex_);
    remote_indexes_.erase(index);
}

void HostMap::try_promote_best(VpnIp vpn_ip) {
    std::unique_lock lock(mutex_);
    unlocked_promote_newest(vpn_ip);
}

void HostMap::unlocked_promote_newest(VpnIp vpn_ip) {
    auto it = hosts_.find(vpn_ip);
    if (it == hosts_.end()) {
        return;
    }
    
    auto primary = it->second;
    if (!primary->next) {
        return;  // Only one host
    }
    
    // Find the newest (last in list) with a connection state
    HostInfo::Ptr best = nullptr;
    auto current = primary;
    
    while (current) {
        if (current->has_connection_state()) {
            best = current;
        }
        current = current->next;
    }
    
    if (best && best != primary) {
        unlocked_make_primary(best);
    }
}

size_t HostMap::size() const {
    std::shared_lock lock(mutex_);
    return hosts_.size();
}

size_t HostMap::index_count() const {
    std::shared_lock lock(mutex_);
    return indexes_.size();
}

size_t HostMap::remote_index_count() const {
    std::shared_lock lock(mutex_);
    return remote_indexes_.size();
}

void HostMap::clear() {
    std::unique_lock lock(mutex_);
    hosts_.clear();
    indexes_.clear();
    remote_indexes_.clear();
}

} // namespace nebula