#pragma once

#include "types.hpp"
#include <boost/json.hpp>
#include <string>
#include <vector>
#include <optional>
#include <filesystem>
#include <map>

namespace nebula {

namespace json = boost::json;

// Forward declarations
struct FirewallRule;

// PKI configuration
struct PkiConfig {
    std::filesystem::path ca;
    std::filesystem::path cert;
    std::filesystem::path key;
    std::vector<std::string> blocklist;  // Certificate fingerprints to block
    
    static Result<PkiConfig> from_json(const json::object& obj);
};

// Listen configuration
struct ListenConfig {
    std::string host = "0.0.0.0";
    uint16_t port = 4242;
    uint32_t batch = 64;
    size_t read_buffer = 10485760;   // 10MB
    size_t write_buffer = 10485760;  // 10MB
    
    static Result<ListenConfig> from_json(const json::object& obj);
};

// TUN device configuration
struct TunConfig {
    std::string dev = "nebula1";
    uint32_t mtu = DEFAULT_MTU;
    std::vector<Route> routes;
    std::vector<Route> unsafe_routes;
    
    static Result<TunConfig> from_json(const json::object& obj);
};

// Connection tracking timeouts
struct ConntrackConfig {
    uint32_t tcp_timeout = 12000;     // seconds
    uint32_t udp_timeout = 60;        // seconds
    uint32_t default_timeout = 60;    // seconds
    
    static Result<ConntrackConfig> from_json(const json::object& obj);
};

// Firewall rule
struct FirewallRule {
    std::optional<uint16_t> port;     // nullopt means "any"
    std::string proto = "any";        // "tcp", "udp", "icmp", "any"
    std::vector<std::string> groups;  // Certificate groups
    std::vector<std::string> hosts;   // Host names or "any"
    std::vector<IpNet> cidrs;         // CIDR blocks
    
    static Result<FirewallRule> from_json(const json::object& obj);
};

// Firewall configuration
struct FirewallConfig {
    ConntrackConfig conntrack;
    std::string outbound_action = "drop";  // "drop" or "accept"
    std::string inbound_action = "drop";   // "drop" or "accept"
    std::vector<FirewallRule> outbound;
    std::vector<FirewallRule> inbound;
    
    static Result<FirewallConfig> from_json(const json::object& obj);
};

// Punchy (UDP hole punching) configuration
struct PunchyConfig {
    bool punch = false;
    bool respond = false;
    std::chrono::seconds delay{1};
    std::chrono::seconds respond_delay{5};
    
    static Result<PunchyConfig> from_json(const json::object& obj);
};

// Logging configuration
struct LoggingConfig {
    std::string level = "info";      // "debug", "info", "warn", "error"
    std::string format = "text";     // "text" or "json"
    bool disable_timestamps = false;
    
    static Result<LoggingConfig> from_json(const json::object& obj);
};

// Main configuration structure
class Config {
public:
    PkiConfig pki;
    std::map<VpnIp, std::vector<Endpoint>> static_host_map;
    ListenConfig listen;
    TunConfig tun;
    FirewallConfig firewall;
    PunchyConfig punchy;
    std::string cipher = "aes";  // "aes" or "chachapoly"
    std::vector<IpNet> preferred_ranges;
    LoggingConfig logging;
    
    // Load configuration from JSON file
    static Result<Config> load_from_file(const std::filesystem::path& path);
    
    // Load configuration from JSON string
    static Result<Config> load_from_string(const std::string& json_str);
    
    // Validate configuration
    Result<void> validate() const;
    
    // Helper function for parsing durations
    static Result<std::chrono::seconds> parse_duration(const json::value& v);
    
private:
    static Result<Config> from_json(const json::value& jv);
};

} // namespace nebula