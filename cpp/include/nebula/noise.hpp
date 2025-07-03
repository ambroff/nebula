#pragma once

#include "types.hpp"
#include "crypto.hpp"
#include <memory>
#include <vector>
#include <optional>

namespace nebula {

// Forward declarations
class HandshakeState;
class CipherState;

// Noise protocol patterns
enum class NoisePattern {
    IX,  // Nebula uses IX pattern
    XX   // Alternative pattern (not used in Nebula)
};

// Handshake role
enum class NoiseRole {
    Initiator,
    Responder
};

// Noise protocol cipher state (for established connections)
class CipherState {
public:
    using Ptr = std::unique_ptr<CipherState>;
    
    // Create cipher state from key
    static Result<Ptr> create(CipherType cipher, const SymmetricKey& key);
    
    // Encrypt with associated data
    Result<std::vector<uint8_t>> encrypt(
        const uint8_t* plaintext, size_t plaintext_len,
        const uint8_t* ad, size_t ad_len,
        uint64_t counter);
    
    // Decrypt with associated data
    Result<std::vector<uint8_t>> decrypt(
        const uint8_t* ciphertext, size_t ciphertext_len,
        const uint8_t* ad, size_t ad_len,
        uint64_t counter);
    
    // Get overhead (tag size)
    size_t overhead() const { return aead_->overhead(); }
    
private:
    CipherState(std::unique_ptr<AEAD> aead, bool big_endian);
    
    std::unique_ptr<AEAD> aead_;
    bool big_endian_;  // true for AES (Nebula default), false for ChaCha
};

// Handshake state for Noise protocol
class HandshakeState {
public:
    using Ptr = std::unique_ptr<HandshakeState>;
    
    // Configuration for handshake
    struct Config {
        NoisePattern pattern = NoisePattern::IX;
        NoiseRole role = NoiseRole::Initiator;
        CipherType cipher = CipherType::AES256_GCM;
        CurveType curve = CurveType::CURVE25519;
        std::shared_ptr<PrivateKey> static_key;
        PublicKey static_public;
        PublicKey remote_static;  // Optional, for responder
        std::vector<uint8_t> prologue;  // Optional
        std::vector<uint8_t> preshared_key;  // Optional (not used in Nebula)
    };
    
    // Create handshake state
    static Result<Ptr> create(const Config& config);
    
    // Process handshake message and generate response
    // Returns: output message, and optionally transport keys if handshake is complete
    struct HandshakeResult {
        std::vector<uint8_t> output;
        std::optional<std::pair<SymmetricKey, SymmetricKey>> transport_keys;  // (send_key, recv_key)
        bool handshake_complete;
    };
    
    // Write handshake message
    Result<HandshakeResult> write_message(
        const uint8_t* payload, size_t payload_len);
    
    // Read handshake message
    Result<HandshakeResult> read_message(
        const uint8_t* message, size_t message_len);
    
    // Get remote static public key (after receiving it in handshake)
    const PublicKey& remote_static() const { return remote_static_; }
    
    // Check if handshake is complete
    bool is_complete() const { return handshake_complete_; }
    
    // Get pattern name (e.g., "Noise_IX_25519_AESGCM_SHA256")
    std::string pattern_name() const;
    
private:
    HandshakeState(const Config& config);
    
    // Handshake operations
    Result<void> mix_hash(const uint8_t* data, size_t len);
    Result<void> mix_key(const uint8_t* data, size_t len);
    Result<std::vector<uint8_t>> encrypt_and_hash(
        const uint8_t* plaintext, size_t len);
    Result<std::vector<uint8_t>> decrypt_and_hash(
        const uint8_t* ciphertext, size_t len);
    
    // Token operations for IX pattern
    Result<void> write_e();  // Write ephemeral key
    Result<void> read_e(const uint8_t*& data, size_t& remaining);
    Result<void> write_s();  // Write static key (encrypted)
    Result<void> read_s(const uint8_t*& data, size_t& remaining);
    Result<void> dh_ee();    // DH(ephemeral, ephemeral)
    Result<void> dh_es();    // DH(ephemeral, static)
    Result<void> dh_se();    // DH(static, ephemeral)
    
    // Split for transport keys
    Result<std::pair<SymmetricKey, SymmetricKey>> split();
    
private:
    Config config_;
    
    // Handshake state
    Hash chaining_key_;
    Hash handshake_hash_;
    std::unique_ptr<AEAD> cipher_;  // Temporary cipher during handshake
    
    // Keys
    std::shared_ptr<PrivateKey> ephemeral_key_;
    PublicKey ephemeral_public_;
    PublicKey remote_ephemeral_;
    PublicKey remote_static_;
    
    // State
    bool handshake_complete_ = false;
    int message_index_ = 0;
    bool has_key_ = false;
};

// Connection state combining both directions
class ConnectionState {
public:
    ConnectionState(
        std::unique_ptr<CipherState> send_cipher,
        std::unique_ptr<CipherState> recv_cipher,
        bool initiator);
    
    // Encrypt outgoing message
    Result<std::vector<uint8_t>> encrypt(
        const uint8_t* plaintext, size_t plaintext_len,
        const uint8_t* header, size_t header_len,
        MessageCounter counter);
    
    // Decrypt incoming message
    Result<std::vector<uint8_t>> decrypt(
        const uint8_t* ciphertext, size_t ciphertext_len,
        const uint8_t* header, size_t header_len,
        MessageCounter counter);
    
    // Check if we initiated the connection
    bool is_initiator() const { return initiator_; }
    
    // Get cipher overhead
    size_t overhead() const { return send_cipher_->overhead(); }
    
private:
    std::unique_ptr<CipherState> send_cipher_;
    std::unique_ptr<CipherState> recv_cipher_;
    bool initiator_;
};

} // namespace nebula