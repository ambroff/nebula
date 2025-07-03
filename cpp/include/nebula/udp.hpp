#pragma once

#include "types.hpp"
#include <boost/asio.hpp>
#include <memory>
#include <functional>
#include <atomic>
#include <thread>
#include <vector>

namespace nebula {

namespace asio = boost::asio;
using udp = asio::ip::udp;

// Forward declarations
class UDPSocket;

// Callback for received packets
using PacketHandler = std::function<void(const uint8_t* data, size_t len, const Endpoint& from)>;

// Statistics for UDP socket
struct UDPStats {
    std::atomic<uint64_t> packets_sent{0};
    std::atomic<uint64_t> packets_received{0};
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_received{0};
    std::atomic<uint64_t> send_errors{0};
    std::atomic<uint64_t> receive_errors{0};
    
    // Default constructor
    UDPStats() = default;
    
    // Copy constructor - loads atomic values
    UDPStats(const UDPStats& other) 
        : packets_sent(other.packets_sent.load())
        , packets_received(other.packets_received.load())
        , bytes_sent(other.bytes_sent.load())
        , bytes_received(other.bytes_received.load())
        , send_errors(other.send_errors.load())
        , receive_errors(other.receive_errors.load()) {}
    
    // Deleted copy assignment
    UDPStats& operator=(const UDPStats&) = delete;
};

// UDP socket configuration
struct UDPConfig {
    std::string bind_host = "0.0.0.0";
    uint16_t bind_port = 4242;
    size_t read_buffer_size = 10485760;   // 10MB
    size_t write_buffer_size = 10485760;  // 10MB
    uint32_t batch_size = 64;             // Number of packets to read in one batch
    bool reuse_addr = true;
    bool reuse_port = false;              // Linux SO_REUSEPORT
};

// Represents a single UDP socket with async I/O
class UDPSocket : public std::enable_shared_from_this<UDPSocket> {
public:
    using Ptr = std::shared_ptr<UDPSocket>;
    
    // Create a new UDP socket
    static Ptr create(asio::io_context& io_context, const UDPConfig& config);
    
    // Destructor
    ~UDPSocket();
    
    // Start receiving packets
    Result<void> start(PacketHandler handler);
    
    // Stop the socket
    void stop();
    
    // Send a packet
    Result<void> send_to(const uint8_t* data, size_t len, const Endpoint& to);
    
    // Send a packet asynchronously
    void async_send_to(const uint8_t* data, size_t len, const Endpoint& to,
                      std::function<void(const boost::system::error_code&, size_t)> handler = nullptr);
    
    // Get local endpoint
    Result<Endpoint> local_endpoint() const;
    
    // Get statistics
    const UDPStats& stats() const { return stats_; }
    
    // Check if socket is running
    bool is_running() const { return running_; }
    
private:
    UDPSocket(asio::io_context& io_context, const UDPConfig& config);
    
    // Start async receive operation
    void start_receive();
    
    // Handle received packet
    void handle_receive(const boost::system::error_code& error, size_t bytes_received);
    
    // Handle sent packet
    void handle_send(const boost::system::error_code& error, size_t bytes_sent);
    
private:
    asio::io_context& io_context_;
    udp::socket socket_;
    UDPConfig config_;
    PacketHandler packet_handler_;
    
    // Receive buffer and endpoint
    std::vector<uint8_t> recv_buffer_;
    udp::endpoint remote_endpoint_;
    
    // State
    std::atomic<bool> running_{false};
    
    // Statistics
    mutable UDPStats stats_;
};

// Multi-threaded UDP server with multiple sockets
class UDPServer {
public:
    UDPServer(size_t num_threads = 1);
    ~UDPServer();
    
    // Add a socket to the server
    void add_socket(UDPSocket::Ptr socket);
    
    // Start the server
    Result<void> start(PacketHandler handler);
    
    // Stop the server
    void stop();
    
    // Send a packet through the first socket
    Result<void> send_to(const uint8_t* data, size_t len, const Endpoint& to);
    
    // Get all sockets
    const std::vector<UDPSocket::Ptr>& sockets() const { return sockets_; }
    
    // Get combined statistics
    UDPStats get_combined_stats() const;
    
private:
    void worker_thread();
    
private:
    asio::io_context io_context_;
    std::unique_ptr<asio::io_context::work> work_;
    std::vector<std::thread> threads_;
    std::vector<UDPSocket::Ptr> sockets_;
    size_t num_threads_;
    std::atomic<bool> running_{false};
};

// Platform-specific optimizations (to be implemented per platform)
namespace platform {
    // Enable platform-specific features like SO_REUSEPORT on Linux
    void optimize_socket(udp::socket& sock, const UDPConfig& config);
}

} // namespace nebula