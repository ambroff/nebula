#include "nebula/types.hpp"
#include <sstream>
#include <stdexcept>

namespace nebula {

IpNet IpNet::from_string(const std::string& cidr) {
    auto slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) {
        throw std::invalid_argument("Invalid CIDR format: missing '/'");
    }
    
    std::string ip_str = cidr.substr(0, slash_pos);
    std::string prefix_str = cidr.substr(slash_pos + 1);
    
    // Parse IP address
    boost::system::error_code ec;
    auto addr = IpAddrV4::from_string(ip_str, ec);
    if (ec) {
        throw std::invalid_argument("Invalid IP address: " + ip_str);
    }
    
    // Parse prefix length
    int prefix = std::stoi(prefix_str);
    if (prefix < 0 || prefix > 32) {
        throw std::invalid_argument("Invalid prefix length: " + prefix_str);
    }
    
    IpNet result;
    result.ip = htonl(addr.to_uint());
    result.prefix_length = static_cast<uint8_t>(prefix);
    
    // Ensure network bits are properly set
    result.ip = result.network();
    
    return result;
}

std::string IpNet::to_string() const {
    std::ostringstream oss;
    oss << vpn_ip_to_string(ip) << "/" << static_cast<int>(prefix_length);
    return oss.str();
}

bool IpNet::contains(VpnIp addr) const {
    if (prefix_length == 0) {
        return true;  // 0.0.0.0/0 contains everything
    }
    
    uint32_t mask_val = mask();
    return (addr & mask_val) == (ip & mask_val);
}

VpnIp IpNet::mask() const {
    if (prefix_length == 0) {
        return 0;
    }
    if (prefix_length >= 32) {
        return 0xFFFFFFFF;
    }
    
    // Create mask with prefix_length bits set to 1
    uint32_t host_mask = 0xFFFFFFFF >> prefix_length;
    return htonl(~host_mask);
}

VpnIp IpNet::network() const {
    return ip & mask();
}

} // namespace nebula