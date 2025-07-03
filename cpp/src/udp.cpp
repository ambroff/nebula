#include "nebula/udp.hpp"
#include <iostream>

namespace nebula {

// Platform-specific socket options
namespace platform {

void optimize_socket(udp::socket& sock, const UDPConfig& config) {
    boost::system::error_code ec;
    
    // Set buffer sizes
    sock.set_option(udp::socket::receive_buffer_size(config.read_buffer_size), ec);
    sock.set_option(udp::socket::send_buffer_size(config.write_buffer_size), ec);
    
    // Reuse address
    if (config.reuse_addr) {
        sock.set_option(udp::socket::reuse_address(true), ec);
    }
    
#ifdef PLATFORM_LINUX
    // Linux-specific optimizations
    if (config.reuse_port) {
        // SO_REUSEPORT for load balancing across threads
        int optval = 1;
        ::setsockopt(sock.native_handle(), SOL_SOCKET, SO_REUSEPORT, 
                    &optval, sizeof(optval));
    }
    
    // Increase receive buffer for high-throughput scenarios
    int rcvbuf = config.read_buffer_size;
    ::setsockopt(sock.native_handle(), SOL_SOCKET, SO_RCVBUFFORCE,
                &rcvbuf, sizeof(rcvbuf));
#endif
}

} // namespace platform

// UDPSocket implementation

UDPSocket::UDPSocket(asio::io_context& io_context, const UDPConfig& config)
    : io_context_(io_context)
    , socket_(io_context)
    , config_(config)
    , recv_buffer_(MTU) {
}

UDPSocket::Ptr UDPSocket::create(asio::io_context& io_context, const UDPConfig& config) {
    return Ptr(new UDPSocket(io_context, config));
}

UDPSocket::~UDPSocket() {
    stop();
}

Result<void> UDPSocket::start(PacketHandler handler) {
    if (running_) {
        return Result<void>("Socket already running");
    }
    
    try {
        // Parse bind address
        boost::system::error_code ec;
        auto addr = asio::ip::address::from_string(config_.bind_host, ec);
        if (ec) {
            return Result<void>("Invalid bind address: " + config_.bind_host);
        }
        
        // Create endpoint
        udp::endpoint endpoint(addr, config_.bind_port);
        
        // Open socket
        socket_.open(endpoint.protocol());
        
        // Apply platform-specific optimizations
        platform::optimize_socket(socket_, config_);
        
        // Bind to endpoint
        socket_.bind(endpoint);
        
        // Store handler and mark as running
        packet_handler_ = std::move(handler);
        running_ = true;
        
        // Start receiving
        start_receive();
        
        return Result<void>();
        
    } catch (const std::exception& e) {
        return Result<void>(std::string("Failed to start socket: ") + e.what());
    }
}

void UDPSocket::stop() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    
    boost::system::error_code ec;
    socket_.cancel(ec);
    socket_.close(ec);
}

void UDPSocket::start_receive() {
    if (!running_) {
        return;
    }
    
    socket_.async_receive_from(
        asio::buffer(recv_buffer_),
        remote_endpoint_,
        [self = shared_from_this()](const boost::system::error_code& error, size_t bytes_received) {
            self->handle_receive(error, bytes_received);
        }
    );
}

void UDPSocket::handle_receive(const boost::system::error_code& error, size_t bytes_received) {
    if (!running_) {
        return;
    }
    
    if (error) {
        stats_.receive_errors++;
        if (error != asio::error::operation_aborted) {
            // Continue receiving despite errors
            start_receive();
        }
        return;
    }
    
    // Update statistics
    stats_.packets_received++;
    stats_.bytes_received += bytes_received;
    
    // Call handler if we have one
    if (packet_handler_ && bytes_received > 0) {
        try {
            packet_handler_(recv_buffer_.data(), bytes_received, remote_endpoint_);
        } catch (const std::exception& e) {
            // Handler threw exception, log but continue
            std::cerr << "Packet handler exception: " << e.what() << std::endl;
        }
    }
    
    // Continue receiving
    start_receive();
}

Result<void> UDPSocket::send_to(const uint8_t* data, size_t len, const Endpoint& to) {
    if (!running_) {
        return Result<void>("Socket not running");
    }
    
    try {
        boost::system::error_code ec;
        size_t sent = socket_.send_to(asio::buffer(data, len), to, 0, ec);
        
        if (ec) {
            stats_.send_errors++;
            return Result<void>("Send failed: " + ec.message());
        }
        
        stats_.packets_sent++;
        stats_.bytes_sent += sent;
        
        return Result<void>();
        
    } catch (const std::exception& e) {
        stats_.send_errors++;
        return Result<void>(std::string("Send exception: ") + e.what());
    }
}

void UDPSocket::async_send_to(const uint8_t* data, size_t len, const Endpoint& to,
                             std::function<void(const boost::system::error_code&, size_t)> handler) {
    if (!running_) {
        if (handler) {
            handler(asio::error::not_connected, 0);
        }
        return;
    }
    
    // Create a copy of the data for async operation
    auto buffer = std::make_shared<std::vector<uint8_t>>(data, data + len);
    
    socket_.async_send_to(
        asio::buffer(*buffer),
        to,
        [this, buffer, handler](const boost::system::error_code& error, size_t bytes_sent) {
            handle_send(error, bytes_sent);
            if (handler) {
                handler(error, bytes_sent);
            }
        }
    );
}

void UDPSocket::handle_send(const boost::system::error_code& error, size_t bytes_sent) {
    if (error) {
        stats_.send_errors++;
    } else {
        stats_.packets_sent++;
        stats_.bytes_sent += bytes_sent;
    }
}

Result<Endpoint> UDPSocket::local_endpoint() const {
    try {
        return socket_.local_endpoint();
    } catch (const std::exception& e) {
        return Result<Endpoint>(std::string("Failed to get local endpoint: ") + e.what());
    }
}

// UDPServer implementation

UDPServer::UDPServer(size_t num_threads)
    : num_threads_(num_threads) {
    work_ = std::make_unique<asio::io_context::work>(io_context_);
}

UDPServer::~UDPServer() {
    stop();
}

void UDPServer::add_socket(UDPSocket::Ptr socket) {
    sockets_.push_back(socket);
}

Result<void> UDPServer::start(PacketHandler handler) {
    if (running_) {
        return Result<void>("Server already running");
    }
    
    // Start all sockets
    for (auto& socket : sockets_) {
        auto result = socket->start(handler);
        if (result.is_error()) {
            // Stop any started sockets
            stop();
            return result;
        }
    }
    
    running_ = true;
    
    // Start worker threads
    for (size_t i = 0; i < num_threads_; ++i) {
        threads_.emplace_back(&UDPServer::worker_thread, this);
    }
    
    return Result<void>();
}

void UDPServer::stop() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    
    // Stop all sockets
    for (auto& socket : sockets_) {
        socket->stop();
    }
    
    // Stop io_context
    work_.reset();
    io_context_.stop();
    
    // Join all threads
    for (auto& thread : threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    threads_.clear();
}

void UDPServer::worker_thread() {
    try {
        io_context_.run();
    } catch (const std::exception& e) {
        std::cerr << "Worker thread exception: " << e.what() << std::endl;
    }
}

Result<void> UDPServer::send_to(const uint8_t* data, size_t len, const Endpoint& to) {
    if (sockets_.empty()) {
        return Result<void>("No sockets available");
    }
    
    // Use first socket for sending
    return sockets_[0]->send_to(data, len, to);
}

UDPStats UDPServer::get_combined_stats() const {
    UDPStats combined;
    
    for (const auto& socket : sockets_) {
        const auto& stats = socket->stats();
        combined.packets_sent += stats.packets_sent.load();
        combined.packets_received += stats.packets_received.load();
        combined.bytes_sent += stats.bytes_sent.load();
        combined.bytes_received += stats.bytes_received.load();
        combined.send_errors += stats.send_errors.load();
        combined.receive_errors += stats.receive_errors.load();
    }
    
    return combined;
}

} // namespace nebula