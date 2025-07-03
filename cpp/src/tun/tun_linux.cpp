#include "nebula/tun.hpp"
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <thread>
#include <atomic>

namespace nebula {

class TunDeviceLinux : public TunDevice {
public:
    TunDeviceLinux(const TunDeviceConfig& config) 
        : TunDevice(config)
        , fd_(-1) {}
    
    ~TunDeviceLinux() override {
        close();
    }
    
    Result<void> open() override {
        if (fd_ >= 0) {
            return Result<void>("Device already open");
        }
        
        // Open TUN device
        fd_ = ::open("/dev/net/tun", O_RDWR);
        if (fd_ < 0) {
            return Result<void>("Failed to open /dev/net/tun: " + std::string(strerror(errno)));
        }
        
        // Configure device
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        
        // IFF_TUN - TUN device (no Ethernet headers)
        // IFF_NO_PI - No packet information
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        
        // Set device name
        if (!config_.name.empty()) {
            strncpy(ifr.ifr_name, config_.name.c_str(), IFNAMSIZ - 1);
        }
        
        if (ioctl(fd_, TUNSETIFF, &ifr) < 0) {
            ::close(fd_);
            fd_ = -1;
            return Result<void>("Failed to configure TUN device: " + std::string(strerror(errno)));
        }
        
        // Save actual device name (kernel might have modified it)
        config_.name = ifr.ifr_name;
        
        // Set non-blocking mode
        int flags = fcntl(fd_, F_GETFL, 0);
        if (flags < 0 || fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
            ::close(fd_);
            fd_ = -1;
            return Result<void>("Failed to set non-blocking mode: " + std::string(strerror(errno)));
        }
        
        // Set MTU
        return set_mtu(config_.mtu);
    }
    
    void close() override {
        stop_async_read();
        
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }
    
    Result<void> configure(VpnIp ip, uint8_t prefix_len) override {
        if (fd_ < 0) {
            return Result<void>("Device not open");
        }
        
        // Get a socket for ioctl operations
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            return Result<void>("Failed to create socket: " + std::string(strerror(errno)));
        }
        
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, config_.name.c_str(), IFNAMSIZ - 1);
        
        // Set IP address
        struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = ip;
        
        if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
            ::close(sock);
            return Result<void>("Failed to set IP address: " + std::string(strerror(errno)));
        }
        
        // Set netmask
        uint32_t mask = 0xFFFFFFFF << (32 - prefix_len);
        addr->sin_addr.s_addr = htonl(mask);
        
        if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
            ::close(sock);
            return Result<void>("Failed to set netmask: " + std::string(strerror(errno)));
        }
        
        // Bring interface up
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
            ::close(sock);
            return Result<void>("Failed to get interface flags: " + std::string(strerror(errno)));
        }
        
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        
        if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
            ::close(sock);
            return Result<void>("Failed to bring interface up: " + std::string(strerror(errno)));
        }
        
        ::close(sock);
        
        // Add configured routes
        for (const auto& route : config_.routes) {
            auto result = add_route(route);
            if (result.is_error()) {
                // Log but don't fail
            }
        }
        
        return Result<void>();
    }
    
    Result<void> add_route(const Route& route) override {
        // This would typically use netlink or route command
        // For now, we'll use the route command as a simple implementation
        std::string cmd = "ip route add " + route.network.to_string() + 
                         " dev " + config_.name;
        
        if (route.via != 0) {
            cmd += " via " + vpn_ip_to_string(route.via);
        }
        
        if (route.metric > 0) {
            cmd += " metric " + std::to_string(route.metric);
        }
        
        int ret = system(cmd.c_str());
        if (ret != 0) {
            return Result<void>("Failed to add route: " + cmd);
        }
        
        return Result<void>();
    }
    
    Result<void> remove_route(const Route& route) override {
        std::string cmd = "ip route del " + route.network.to_string() + 
                         " dev " + config_.name;
        
        int ret = system(cmd.c_str());
        if (ret != 0) {
            return Result<void>("Failed to remove route: " + cmd);
        }
        
        return Result<void>();
    }
    
    Result<size_t> read(uint8_t* buffer, size_t max_len) override {
        if (fd_ < 0) {
            return Result<size_t>("Device not open");
        }
        
        ssize_t n = ::read(fd_, buffer, max_len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return Result<size_t>(size_t(0));
            }
            stats_.errors++;
            return Result<size_t>("Read failed: " + std::string(strerror(errno)));
        }
        
        stats_.packets_received++;
        stats_.bytes_received += n;
        
        return Result<size_t>(size_t(n));
    }
    
    Result<void> write(const uint8_t* data, size_t len) override {
        if (fd_ < 0) {
            return Result<void>("Device not open");
        }
        
        ssize_t n = ::write(fd_, data, len);
        if (n < 0) {
            stats_.errors++;
            return Result<void>("Write failed: " + std::string(strerror(errno)));
        }
        
        if (size_t(n) != len) {
            stats_.errors++;
            return Result<void>("Partial write: " + std::to_string(n) + "/" + std::to_string(len));
        }
        
        stats_.packets_sent++;
        stats_.bytes_sent += n;
        
        return Result<void>();
    }
    
    Result<void> start_async_read(TunPacketHandler handler) override {
        if (fd_ < 0) {
            return Result<void>("Device not open");
        }
        
        if (read_thread_.joinable()) {
            return Result<void>("Async read already started");
        }
        
        packet_handler_ = handler;
        reading_ = true;
        
        read_thread_ = std::thread([this]() {
            read_loop();
        });
        
        return Result<void>();
    }
    
    void stop_async_read() override {
        reading_ = false;
        
        if (read_thread_.joinable()) {
            read_thread_.join();
        }
    }
    
    bool is_open() const override {
        return fd_ >= 0;
    }
    
    int fd() const override {
        return fd_;
    }
    
private:
    Result<void> set_mtu(uint32_t mtu) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            return Result<void>("Failed to create socket: " + std::string(strerror(errno)));
        }
        
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, config_.name.c_str(), IFNAMSIZ - 1);
        ifr.ifr_mtu = mtu;
        
        if (ioctl(sock, SIOCSIFMTU, &ifr) < 0) {
            ::close(sock);
            return Result<void>("Failed to set MTU: " + std::string(strerror(errno)));
        }
        
        ::close(sock);
        return Result<void>();
    }
    
    void read_loop() {
        std::vector<uint8_t> buffer(MTU);
        
        while (reading_) {
            ssize_t n = ::read(fd_, buffer.data(), buffer.size());
            
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // No data available, sleep briefly
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    continue;
                }
                
                if (errno == EINTR) {
                    continue;
                }
                
                // Error occurred
                stats_.errors++;
                break;
            }
            
            if (n == 0) {
                // EOF?
                break;
            }
            
            stats_.packets_received++;
            stats_.bytes_received += n;
            
            if (packet_handler_) {
                try {
                    packet_handler_(buffer.data(), n);
                } catch (...) {
                    // Ignore handler exceptions
                }
            }
        }
    }
    
private:
    int fd_;
    std::atomic<bool> reading_{false};
    std::thread read_thread_;
    TunPacketHandler packet_handler_;
};

// Factory function implementation
Result<TunDevice::Ptr> TunDevice::create(const TunDeviceConfig& config) {
    return Result<TunDevice::Ptr>(std::make_shared<TunDeviceLinux>(config));
}

} // namespace nebula