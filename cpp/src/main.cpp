#include "nebula/types.hpp"
#include "nebula/header.hpp"
#include "nebula/config.hpp"
#include "nebula/udp.hpp"
#include "nebula/tun.hpp"
#include "nebula/crypto.hpp"
#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <cstring>

using namespace nebula;

void test_types() {
    std::cout << "=== Testing Types ===" << std::endl;
    
    // Test VpnIp conversion
    VpnIp ip = string_to_vpn_ip("192.168.1.1");
    std::cout << "VpnIp for 192.168.1.1: 0x" << std::hex << ip << std::dec << std::endl;
    std::cout << "Back to string: " << vpn_ip_to_string(ip) << std::endl;
    
    // Test IpNet
    auto net = IpNet::from_string("192.168.1.0/24");
    std::cout << "IpNet: " << net.to_string() << std::endl;
    std::cout << "Contains 192.168.1.100: " << net.contains(string_to_vpn_ip("192.168.1.100")) << std::endl;
    std::cout << "Contains 192.168.2.1: " << net.contains(string_to_vpn_ip("192.168.2.1")) << std::endl;
    
    std::cout << std::endl;
}

void test_header() {
    std::cout << "=== Testing Header ===" << std::endl;
    
    // Create a header
    Header h(MessageType::Handshake, MessageSubType::HandshakeIXPSK0, 12345, 67890);
    std::cout << "Original: " << h.to_string() << std::endl;
    
    // Encode to buffer
    uint8_t buffer[HEADER_LEN];
    h.encode(buffer);
    
    std::cout << "Encoded bytes: ";
    for (size_t i = 0; i < HEADER_LEN; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(buffer[i]) << " ";
    }
    std::cout << std::dec << std::endl;
    
    // Decode back
    Header h2;
    if (h2.decode(buffer, HEADER_LEN)) {
        std::cout << "Decoded: " << h2.to_string() << std::endl;
        std::cout << "Decode successful!" << std::endl;
    } else {
        std::cout << "Decode failed!" << std::endl;
    }
    
    std::cout << std::endl;
}

void test_result() {
    std::cout << "=== Testing Result Type ===" << std::endl;
    
    // Success case
    Result<int> r1(42);
    if (r1.ok()) {
        std::cout << "Success result value: " << r1.value() << std::endl;
    }
    
    // Error case
    Result<int> r2("Something went wrong");
    if (r2.is_error()) {
        std::cout << "Error result: " << r2.error() << std::endl;
    }
    
    // Void result
    Result<void> r3;
    std::cout << "Void result ok: " << r3.ok() << std::endl;
    
    Result<void> r4("Error");
    std::cout << "Void error result: " << r4.error() << std::endl;
    
    std::cout << std::endl;
}

void test_config() {
    std::cout << "=== Testing Configuration ===" << std::endl;
    
    // Test loading from example config
    auto config_result = Config::load_from_file("examples/config.json");
    if (config_result.is_error()) {
        std::cout << "Failed to load config: " << config_result.error() << std::endl;
        return;
    }
    
    const auto& config = config_result.value();
    std::cout << "Config loaded successfully!" << std::endl;
    std::cout << "  PKI CA: " << config.pki.ca << std::endl;
    std::cout << "  Listen: " << config.listen.host << ":" << config.listen.port << std::endl;
    std::cout << "  TUN device: " << config.tun.dev << " (MTU: " << config.tun.mtu << ")" << std::endl;
    std::cout << "  Cipher: " << config.cipher << std::endl;
    std::cout << "  Punchy enabled: " << (config.punchy.punch ? "yes" : "no") << std::endl;
    std::cout << "  Static hosts: " << config.static_host_map.size() << std::endl;
    std::cout << "  Firewall inbound rules: " << config.firewall.inbound.size() << std::endl;
    std::cout << "  Firewall outbound rules: " << config.firewall.outbound.size() << std::endl;
    
    // Test config validation (will fail because PKI files don't exist)
    auto validate_result = config.validate();
    if (validate_result.is_error()) {
        std::cout << "Validation failed (expected): " << validate_result.error() << std::endl;
    } else {
        std::cout << "Validation passed!" << std::endl;
    }
    
    std::cout << std::endl;
}

void test_udp() {
    std::cout << "=== Testing UDP Socket ===" << std::endl;
    
    asio::io_context io_context;
    
    // Create UDP socket
    UDPConfig config;
    config.bind_host = "127.0.0.1";
    config.bind_port = 0;  // Let OS choose port
    
    auto socket = UDPSocket::create(io_context, config);
    
    // Start socket with packet handler
    bool packet_received = false;
    auto start_result = socket->start([&packet_received](const uint8_t*, size_t len, const Endpoint& from) {
        std::cout << "Received " << len << " bytes from " << from << std::endl;
        packet_received = true;
    });
    
    if (start_result.is_error()) {
        std::cout << "Failed to start socket: " << start_result.error() << std::endl;
        return;
    }
    
    // Get local endpoint
    auto endpoint_result = socket->local_endpoint();
    if (endpoint_result.ok()) {
        std::cout << "Socket listening on: " << endpoint_result.value() << std::endl;
    }
    
    // Send a test packet to ourselves
    const char* test_data = "Hello, Nebula!";
    socket->send_to(reinterpret_cast<const uint8_t*>(test_data), 
                   strlen(test_data), endpoint_result.value());
    
    // Run io_context briefly to process the packet
    io_context.run_for(std::chrono::milliseconds(100));
    
    // Check stats
    const auto& stats = socket->stats();
    std::cout << "Stats: sent=" << stats.packets_sent << " received=" << stats.packets_received << std::endl;
    
    socket->stop();
    std::cout << std::endl;
}

void test_tun() {
    std::cout << "=== Testing TUN Device ===" << std::endl;
    
    TunDeviceConfig config;
    config.name = "nebula-test";
    config.mtu = 1300;
    
    auto tun_result = TunDevice::create(config);
    if (tun_result.is_error()) {
        std::cout << "Failed to create TUN device: " << tun_result.error() << std::endl;
        return;
    }
    
    auto tun = tun_result.value();
    
    // Try to open (will likely fail without root)
    auto open_result = tun->open();
    if (open_result.is_error()) {
        std::cout << "Failed to open TUN device (expected without root): " << open_result.error() << std::endl;
    } else {
        std::cout << "TUN device opened: " << tun->name() << std::endl;
        std::cout << "MTU: " << tun->mtu() << std::endl;
        tun->close();
    }
    
    std::cout << std::endl;
}

void test_crypto() {
    std::cout << "=== Testing Crypto ===" << std::endl;
    
    // Initialize crypto
    auto init_result = init_crypto();
    if (init_result.is_error()) {
        std::cout << "Failed to init crypto: " << init_result.error() << std::endl;
        return;
    }
    
    // Test key generation
    auto kp1_result = generate_keypair(CurveType::CURVE25519);
    auto kp2_result = generate_keypair(CurveType::CURVE25519);
    
    if (kp1_result.is_error() || kp2_result.is_error()) {
        std::cout << "Failed to generate keypairs" << std::endl;
        return;
    }
    
    auto kp1 = kp1_result.value();
    auto kp2 = kp2_result.value();
    
    std::cout << "Generated Curve25519 keypairs" << std::endl;
    std::cout << "  KP1 public: " << kp1.public_key.to_hex().substr(0, 16) << "..." << std::endl;
    std::cout << "  KP2 public: " << kp2.public_key.to_hex().substr(0, 16) << "..." << std::endl;
    
    // Test ECDH
    auto shared1_result = kp1.private_key->ecdh(kp2.public_key);
    auto shared2_result = kp2.private_key->ecdh(kp1.public_key);
    
    if (shared1_result.is_error() || shared2_result.is_error()) {
        std::cout << "ECDH failed" << std::endl;
        return;
    }
    
    auto shared1 = shared1_result.value();
    auto shared2 = shared2_result.value();
    
    if (shared1 == shared2) {
        std::cout << "ECDH successful - shared secrets match!" << std::endl;
    } else {
        std::cout << "ECDH failed - shared secrets don't match!" << std::endl;
    }
    
    // Test AES-GCM
    auto aead_result = AEAD::create(CipherType::AES256_GCM, shared1);
    if (aead_result.is_error()) {
        std::cout << "Failed to create AEAD: " << aead_result.error() << std::endl;
        return;
    }
    
    auto aead = std::move(aead_result.value());
    
    // Test encryption/decryption
    const char* plaintext = "Hello, Nebula encryption!";
    size_t plaintext_len = strlen(plaintext);
    
    Nonce nonce = make_nonce(42);
    const char* ad = "additional data";
    
    auto encrypt_result = aead->encrypt(
        reinterpret_cast<const uint8_t*>(plaintext), plaintext_len,
        reinterpret_cast<const uint8_t*>(ad), strlen(ad),
        nonce);
    
    if (encrypt_result.is_error()) {
        std::cout << "Encryption failed: " << encrypt_result.error() << std::endl;
        return;
    }
    
    auto ciphertext = encrypt_result.value();
    std::cout << "Encrypted " << plaintext_len << " bytes -> " << ciphertext.size() << " bytes" << std::endl;
    
    auto decrypt_result = aead->decrypt(
        ciphertext.data(), ciphertext.size(),
        reinterpret_cast<const uint8_t*>(ad), strlen(ad),
        nonce);
    
    if (decrypt_result.is_error()) {
        std::cout << "Decryption failed: " << decrypt_result.error() << std::endl;
        return;
    }
    
    auto decrypted = decrypt_result.value();
    if (decrypted.size() == plaintext_len &&
        memcmp(decrypted.data(), plaintext, plaintext_len) == 0) {
        std::cout << "Decryption successful - plaintext recovered!" << std::endl;
    } else {
        std::cout << "Decryption failed - plaintext mismatch!" << std::endl;
    }
    
    // Test hashing
    auto hash_result = sha256(reinterpret_cast<const uint8_t*>("test"), 4);
    if (hash_result.ok()) {
        std::cout << "SHA256('test') = ";
        for (size_t i = 0; i < 8; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << static_cast<int>(hash_result.value()[i]);
        }
        std::cout << "..." << std::dec << std::endl;
    }
    
    cleanup_crypto();
    std::cout << std::endl;
}

int main() {
    std::cout << "Nebula C++ Port - Basic Tests" << std::endl;
    std::cout << "=============================" << std::endl << std::endl;
    
    try {
        test_types();
        test_header();
        test_result();
        test_config();
        test_udp();
        test_tun();
        test_crypto();
        
        std::cout << "All tests completed!" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}