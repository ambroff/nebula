#include "nebula/config.hpp"
#include <fstream>
#include <sstream>
#include <regex>

namespace nebula {

namespace {

// Helper to get optional value from JSON object
template<typename T>
std::optional<T> get_optional(const json::object& obj, const std::string& key) {
    auto it = obj.find(key);
    if (it != obj.end() && !it->value().is_null()) {
        try {
            return json::value_to<T>(it->value());
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }
    return std::nullopt;
}

// Helper to get value with default
template<typename T>
T get_value_or(const json::object& obj, const std::string& key, const T& default_value) {
    auto opt = get_optional<T>(obj, key);
    return opt.value_or(default_value);
}

} // anonymous namespace

Result<std::chrono::seconds> Config::parse_duration(const json::value& v) {
    if (v.is_number()) {
        return std::chrono::seconds(v.as_int64());
    }
    
    if (v.is_string()) {
        std::string str = v.as_string().c_str();
        std::regex duration_regex(R"((\d+)([smh])?)");
        std::smatch match;
        
        if (std::regex_match(str, match, duration_regex)) {
            int64_t value = std::stoll(match[1]);
            std::string unit = match[2];
            
            if (unit.empty() || unit == "s") {
                return std::chrono::seconds(value);
            } else if (unit == "m") {
                return std::chrono::seconds(value * 60);
            } else if (unit == "h") {
                return std::chrono::seconds(value * 3600);
            }
        }
        return Result<std::chrono::seconds>("Invalid duration format: " + str);
    }
    
    return Result<std::chrono::seconds>("Duration must be number or string");
}

Result<PkiConfig> PkiConfig::from_json(const json::object& obj) {
    PkiConfig config;
    
    auto ca_it = obj.find("ca");
    if (ca_it == obj.end()) {
        return Result<PkiConfig>("Missing required field: pki.ca");
    }
    config.ca = ca_it->value().as_string().c_str();
    
    auto cert_it = obj.find("cert");
    if (cert_it == obj.end()) {
        return Result<PkiConfig>("Missing required field: pki.cert");
    }
    config.cert = cert_it->value().as_string().c_str();
    
    auto key_it = obj.find("key");
    if (key_it == obj.end()) {
        return Result<PkiConfig>("Missing required field: pki.key");
    }
    config.key = key_it->value().as_string().c_str();
    
    auto blocklist_it = obj.find("blocklist");
    if (blocklist_it != obj.end() && blocklist_it->value().is_array()) {
        for (const auto& item : blocklist_it->value().as_array()) {
            config.blocklist.push_back(item.as_string().c_str());
        }
    }
    
    return config;
}

Result<ListenConfig> ListenConfig::from_json(const json::object& obj) {
    ListenConfig config;
    
    config.host = get_value_or<std::string>(obj, "host", "0.0.0.0");
    config.port = get_value_or<int64_t>(obj, "port", 4242);
    config.batch = get_value_or<int64_t>(obj, "batch", 64);
    config.read_buffer = get_value_or<int64_t>(obj, "read_buffer", 10485760);
    config.write_buffer = get_value_or<int64_t>(obj, "write_buffer", 10485760);
    
    return config;
}

Result<TunConfig> TunConfig::from_json(const json::object& obj) {
    TunConfig config;
    
    config.dev = get_value_or<std::string>(obj, "dev", "nebula1");
    config.mtu = get_value_or<int64_t>(obj, "mtu", DEFAULT_MTU);
    
    // Parse routes
    auto routes_it = obj.find("routes");
    if (routes_it != obj.end() && routes_it->value().is_array()) {
        for (const auto& route_val : routes_it->value().as_array()) {
            if (!route_val.is_object()) continue;
            
            const auto& route_obj = route_val.as_object();
            auto net_it = route_obj.find("network");
            if (net_it == route_obj.end()) continue;
            
            try {
                auto net = IpNet::from_string(net_it->value().as_string().c_str());
                uint32_t metric = get_value_or<int64_t>(route_obj, "metric", 0);
                config.routes.emplace_back(net, 0, metric);
            } catch (const std::exception& e) {
                return Result<TunConfig>(std::string("Invalid route network: ") + e.what());
            }
        }
    }
    
    // Parse unsafe_routes
    auto unsafe_it = obj.find("unsafe_routes");
    if (unsafe_it != obj.end() && unsafe_it->value().is_array()) {
        for (const auto& route_val : unsafe_it->value().as_array()) {
            if (!route_val.is_object()) continue;
            
            const auto& route_obj = route_val.as_object();
            auto net_it = route_obj.find("network");
            auto via_it = route_obj.find("via");
            
            if (net_it == route_obj.end() || via_it == route_obj.end()) continue;
            
            try {
                auto net = IpNet::from_string(net_it->value().as_string().c_str());
                auto via = string_to_vpn_ip(via_it->value().as_string().c_str());
                uint32_t metric = get_value_or<int64_t>(route_obj, "metric", 0);
                config.unsafe_routes.emplace_back(net, via, metric);
            } catch (const std::exception& e) {
                return Result<TunConfig>(std::string("Invalid unsafe_route: ") + e.what());
            }
        }
    }
    
    return config;
}

Result<ConntrackConfig> ConntrackConfig::from_json(const json::object& obj) {
    ConntrackConfig config;
    
    config.tcp_timeout = get_value_or<int64_t>(obj, "tcp_timeout", 12000);
    config.udp_timeout = get_value_or<int64_t>(obj, "udp_timeout", 60);
    config.default_timeout = get_value_or<int64_t>(obj, "default_timeout", 60);
    
    return config;
}

Result<FirewallRule> FirewallRule::from_json(const json::object& obj) {
    FirewallRule rule;
    
    // Parse port
    auto port_it = obj.find("port");
    if (port_it != obj.end()) {
        if (port_it->value().is_string() && port_it->value().as_string() == "any") {
            rule.port = std::nullopt;
        } else if (port_it->value().is_number()) {
            rule.port = port_it->value().as_int64();
        }
    }
    
    // Parse protocol
    rule.proto = get_value_or<std::string>(obj, "proto", "any");
    
    // Parse groups
    auto groups_it = obj.find("groups");
    if (groups_it != obj.end() && groups_it->value().is_array()) {
        for (const auto& group : groups_it->value().as_array()) {
            rule.groups.push_back(group.as_string().c_str());
        }
    }
    
    // Parse hosts
    auto hosts_it = obj.find("hosts");
    if (hosts_it != obj.end() && hosts_it->value().is_array()) {
        for (const auto& host : hosts_it->value().as_array()) {
            rule.hosts.push_back(host.as_string().c_str());
        }
    } else {
        auto host_it = obj.find("host");
        if (host_it != obj.end()) {
            rule.hosts.push_back(host_it->value().as_string().c_str());
        }
    }
    
    // Parse CIDRs
    auto cidrs_it = obj.find("cidrs");
    if (cidrs_it != obj.end() && cidrs_it->value().is_array()) {
        for (const auto& cidr : cidrs_it->value().as_array()) {
            try {
                rule.cidrs.push_back(IpNet::from_string(cidr.as_string().c_str()));
            } catch (const std::exception& e) {
                return Result<FirewallRule>(std::string("Invalid CIDR: ") + e.what());
            }
        }
    } else {
        auto cidr_it = obj.find("cidr");
        if (cidr_it != obj.end()) {
            try {
                rule.cidrs.push_back(IpNet::from_string(cidr_it->value().as_string().c_str()));
            } catch (const std::exception& e) {
                return Result<FirewallRule>(std::string("Invalid CIDR: ") + e.what());
            }
        }
    }
    
    return rule;
}

Result<FirewallConfig> FirewallConfig::from_json(const json::object& obj) {
    FirewallConfig config;
    
    // Parse conntrack
    auto ct_it = obj.find("conntrack");
    if (ct_it != obj.end() && ct_it->value().is_object()) {
        auto ct_result = ConntrackConfig::from_json(ct_it->value().as_object());
        if (ct_result.is_error()) {
            return Result<FirewallConfig>("Failed to parse conntrack: " + ct_result.error());
        }
        config.conntrack = ct_result.value();
    }
    
    config.outbound_action = get_value_or<std::string>(obj, "outbound_action", "drop");
    config.inbound_action = get_value_or<std::string>(obj, "inbound_action", "drop");
    
    // Parse outbound rules
    auto out_it = obj.find("outbound");
    if (out_it != obj.end() && out_it->value().is_array()) {
        for (const auto& rule_val : out_it->value().as_array()) {
            if (!rule_val.is_object()) continue;
            
            auto rule_result = FirewallRule::from_json(rule_val.as_object());
            if (rule_result.is_error()) {
                return Result<FirewallConfig>("Failed to parse outbound rule: " + rule_result.error());
            }
            config.outbound.push_back(rule_result.value());
        }
    }
    
    // Parse inbound rules
    auto in_it = obj.find("inbound");
    if (in_it != obj.end() && in_it->value().is_array()) {
        for (const auto& rule_val : in_it->value().as_array()) {
            if (!rule_val.is_object()) continue;
            
            auto rule_result = FirewallRule::from_json(rule_val.as_object());
            if (rule_result.is_error()) {
                return Result<FirewallConfig>("Failed to parse inbound rule: " + rule_result.error());
            }
            config.inbound.push_back(rule_result.value());
        }
    }
    
    return config;
}

Result<PunchyConfig> PunchyConfig::from_json(const json::object& obj) {
    PunchyConfig config;
    
    config.punch = get_value_or<bool>(obj, "punch", false);
    config.respond = get_value_or<bool>(obj, "respond", false);
    
    auto delay_it = obj.find("delay");
    if (delay_it != obj.end()) {
        auto delay_result = Config::parse_duration(delay_it->value());
        if (delay_result.is_error()) {
            return Result<PunchyConfig>("Failed to parse delay: " + delay_result.error());
        }
        config.delay = delay_result.value();
    }
    
    auto respond_delay_it = obj.find("respond_delay");
    if (respond_delay_it != obj.end()) {
        auto delay_result = Config::parse_duration(respond_delay_it->value());
        if (delay_result.is_error()) {
            return Result<PunchyConfig>("Failed to parse respond_delay: " + delay_result.error());
        }
        config.respond_delay = delay_result.value();
    }
    
    return config;
}

Result<LoggingConfig> LoggingConfig::from_json(const json::object& obj) {
    LoggingConfig config;
    
    config.level = get_value_or<std::string>(obj, "level", "info");
    config.format = get_value_or<std::string>(obj, "format", "text");
    config.disable_timestamps = get_value_or<bool>(obj, "disable_timestamps", false);
    
    return config;
}

Result<Config> Config::from_json(const json::value& jv) {
    if (!jv.is_object()) {
        return Result<Config>("Configuration must be a JSON object");
    }
    
    const auto& obj = jv.as_object();
    Config config;
    
    // Parse PKI (required)
    auto pki_it = obj.find("pki");
    if (pki_it == obj.end() || !pki_it->value().is_object()) {
        return Result<Config>("Missing required field: pki");
    }
    auto pki_result = PkiConfig::from_json(pki_it->value().as_object());
    if (pki_result.is_error()) {
        return Result<Config>("Failed to parse pki: " + pki_result.error());
    }
    config.pki = pki_result.value();
    
    // Parse static_host_map
    auto shm_it = obj.find("static_host_map");
    if (shm_it != obj.end() && shm_it->value().is_object()) {
        for (const auto& [key, value] : shm_it->value().as_object()) {
            try {
                VpnIp vpn_ip = string_to_vpn_ip(key);
                std::vector<Endpoint> endpoints;
                
                if (value.is_array()) {
                    for (const auto& endpoint_val : value.as_array()) {
                        std::string endpoint_str = endpoint_val.as_string().c_str();
                        // Parse "host:port" format
                        auto colon_pos = endpoint_str.rfind(':');
                        if (colon_pos != std::string::npos) {
                            std::string host = endpoint_str.substr(0, colon_pos);
                            uint16_t port = std::stoi(endpoint_str.substr(colon_pos + 1));
                            
                            boost::system::error_code ec;
                            auto addr = boost::asio::ip::address::from_string(host, ec);
                            if (!ec) {
                                endpoints.emplace_back(addr, port);
                            }
                        }
                    }
                }
                
                if (!endpoints.empty()) {
                    config.static_host_map[vpn_ip] = endpoints;
                }
            } catch (const std::exception& e) {
                return Result<Config>(std::string("Invalid static_host_map entry: ") + e.what());
            }
        }
    }
    
    // Parse listen
    auto listen_it = obj.find("listen");
    if (listen_it != obj.end() && listen_it->value().is_object()) {
        auto listen_result = ListenConfig::from_json(listen_it->value().as_object());
        if (listen_result.is_error()) {
            return Result<Config>("Failed to parse listen: " + listen_result.error());
        }
        config.listen = listen_result.value();
    }
    
    // Parse tun
    auto tun_it = obj.find("tun");
    if (tun_it != obj.end() && tun_it->value().is_object()) {
        auto tun_result = TunConfig::from_json(tun_it->value().as_object());
        if (tun_result.is_error()) {
            return Result<Config>("Failed to parse tun: " + tun_result.error());
        }
        config.tun = tun_result.value();
    }
    
    // Parse firewall
    auto fw_it = obj.find("firewall");
    if (fw_it != obj.end() && fw_it->value().is_object()) {
        auto fw_result = FirewallConfig::from_json(fw_it->value().as_object());
        if (fw_result.is_error()) {
            return Result<Config>("Failed to parse firewall: " + fw_result.error());
        }
        config.firewall = fw_result.value();
    }
    
    // Parse punchy
    auto punchy_it = obj.find("punchy");
    if (punchy_it != obj.end() && punchy_it->value().is_object()) {
        auto punchy_result = PunchyConfig::from_json(punchy_it->value().as_object());
        if (punchy_result.is_error()) {
            return Result<Config>("Failed to parse punchy: " + punchy_result.error());
        }
        config.punchy = punchy_result.value();
    }
    
    // Parse cipher
    config.cipher = get_value_or<std::string>(obj, "cipher", "aes");
    
    // Parse preferred_ranges
    auto pr_it = obj.find("preferred_ranges");
    if (pr_it != obj.end() && pr_it->value().is_array()) {
        for (const auto& range_val : pr_it->value().as_array()) {
            try {
                config.preferred_ranges.push_back(
                    IpNet::from_string(range_val.as_string().c_str())
                );
            } catch (const std::exception& e) {
                return Result<Config>(std::string("Invalid preferred_range: ") + e.what());
            }
        }
    }
    
    // Parse logging
    auto log_it = obj.find("logging");
    if (log_it != obj.end() && log_it->value().is_object()) {
        auto log_result = LoggingConfig::from_json(log_it->value().as_object());
        if (log_result.is_error()) {
            return Result<Config>("Failed to parse logging: " + log_result.error());
        }
        config.logging = log_result.value();
    }
    
    return config;
}

Result<Config> Config::load_from_file(const std::filesystem::path& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return Result<Config>("Failed to open config file: " + path.string());
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    return load_from_string(buffer.str());
}

Result<Config> Config::load_from_string(const std::string& json_str) {
    try {
        json::value jv = json::parse(json_str);
        return from_json(jv);
    } catch (const std::exception& e) {
        return Result<Config>(std::string("JSON parse error: ") + e.what());
    }
}

Result<void> Config::validate() const {
    // Validate PKI paths exist
    if (!std::filesystem::exists(pki.ca)) {
        return Result<void>("CA certificate not found: " + pki.ca.string());
    }
    if (!std::filesystem::exists(pki.cert)) {
        return Result<void>("Certificate not found: " + pki.cert.string());
    }
    if (!std::filesystem::exists(pki.key)) {
        return Result<void>("Private key not found: " + pki.key.string());
    }
    
    // Validate cipher
    if (cipher != "aes" && cipher != "chachapoly") {
        return Result<void>("Invalid cipher: " + cipher + " (must be 'aes' or 'chachapoly')");
    }
    
    // Validate MTU
    if (tun.mtu < MIN_MTU || tun.mtu > MTU) {
        return Result<void>("Invalid MTU: " + std::to_string(tun.mtu) + 
                           " (must be between " + std::to_string(MIN_MTU) + 
                           " and " + std::to_string(MTU) + ")");
    }
    
    // Validate firewall actions
    if (firewall.outbound_action != "drop" && firewall.outbound_action != "accept") {
        return Result<void>("Invalid outbound_action: " + firewall.outbound_action);
    }
    if (firewall.inbound_action != "drop" && firewall.inbound_action != "accept") {
        return Result<void>("Invalid inbound_action: " + firewall.inbound_action);
    }
    
    // Validate logging
    if (logging.level != "debug" && logging.level != "info" && 
        logging.level != "warn" && logging.level != "error") {
        return Result<void>("Invalid logging level: " + logging.level);
    }
    if (logging.format != "text" && logging.format != "json") {
        return Result<void>("Invalid logging format: " + logging.format);
    }
    
    return Result<void>();
}

} // namespace nebula