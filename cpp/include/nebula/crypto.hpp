#pragma once

#include "types.hpp"
#include <array>
#include <memory>
#include <string>

namespace nebula {

// Crypto algorithm types
enum class CipherType {
    AES256_GCM,
    CHACHA20_POLY1305
};

enum class CurveType {
    CURVE25519,
    P256
};

// Key sizes
constexpr size_t AES_256_KEY_SIZE = 32;
constexpr size_t CHACHA20_KEY_SIZE = 32;
constexpr size_t CURVE25519_KEY_SIZE = 32;
constexpr size_t P256_KEY_SIZE = 32;  // Compressed point
constexpr size_t NONCE_SIZE = 12;
constexpr size_t GCM_TAG_SIZE = 16;
constexpr size_t POLY1305_TAG_SIZE = 16;
constexpr size_t SHA256_HASH_SIZE = 32;

// Key types
using SymmetricKey = std::array<uint8_t, 32>;
using Nonce = std::array<uint8_t, NONCE_SIZE>;
using Hash = std::array<uint8_t, SHA256_HASH_SIZE>;

// Forward declarations
class PrivateKey;
class AEAD;

// Public key wrapper
class PublicKey {
public:
    PublicKey() = default;
    explicit PublicKey(const std::vector<uint8_t>& data, CurveType curve);
    
    // Get raw bytes
    const std::vector<uint8_t>& bytes() const { return data_; }
    
    // Get curve type
    CurveType curve() const { return curve_; }
    
    // Check if key is valid
    bool is_valid() const { return !data_.empty(); }
    
    // Convert to hex string
    std::string to_hex() const;
    
    // Create from hex string
    static Result<PublicKey> from_hex(const std::string& hex, CurveType curve);
    
private:
    std::vector<uint8_t> data_;
    CurveType curve_ = CurveType::CURVE25519;
};

// Private key wrapper (opaque)
class PrivateKey {
public:
    virtual ~PrivateKey() = default;
    
    // Perform ECDH with another public key
    virtual Result<SymmetricKey> ecdh(const PublicKey& peer_public) const = 0;
    
    // Get associated public key
    virtual PublicKey public_key() const = 0;
    
    // Get curve type
    virtual CurveType curve() const = 0;
    
    // Export private key bytes (for storage)
    virtual std::vector<uint8_t> export_key() const = 0;
    
    // Import private key from bytes
    static Result<std::shared_ptr<PrivateKey>> import_key(
        const std::vector<uint8_t>& data, CurveType curve);
};

// Diffie-Hellman result
struct DHResult {
    PublicKey public_key;
    std::shared_ptr<PrivateKey> private_key;
};

// Generate a new DH keypair
Result<DHResult> generate_keypair(CurveType curve);

// AEAD cipher interface
class AEAD {
public:
    using Ptr = std::unique_ptr<AEAD>;
    
    virtual ~AEAD() = default;
    
    // Create AEAD cipher
    static Result<Ptr> create(CipherType cipher, const SymmetricKey& key);
    
    // Encrypt data
    virtual Result<std::vector<uint8_t>> encrypt(
        const uint8_t* plaintext, size_t len,
        const uint8_t* additional_data, size_t ad_len,
        const Nonce& nonce) = 0;
    
    // Decrypt data
    virtual Result<std::vector<uint8_t>> decrypt(
        const uint8_t* ciphertext, size_t len,
        const uint8_t* additional_data, size_t ad_len,
        const Nonce& nonce) = 0;
    
    // Get overhead size (tag length)
    virtual size_t overhead() const = 0;
    
    // Encrypt in-place (output buffer must have room for tag)
    virtual Result<size_t> encrypt_in_place(
        uint8_t* data, size_t len, size_t max_len,
        const uint8_t* additional_data, size_t ad_len,
        const Nonce& nonce) = 0;
    
    // Decrypt in-place
    virtual Result<size_t> decrypt_in_place(
        uint8_t* data, size_t len,
        const uint8_t* additional_data, size_t ad_len,
        const Nonce& nonce) = 0;
};

// Hash functions
Result<Hash> sha256(const uint8_t* data, size_t len);
Result<Hash> sha256(const std::vector<uint8_t>& data);

// HMAC functions
Result<Hash> hmac_sha256(const SymmetricKey& key, const uint8_t* data, size_t len);

// Random number generation
Result<void> random_bytes(uint8_t* out, size_t len);
Result<std::vector<uint8_t>> random_bytes(size_t len);

// Key derivation (HKDF)
Result<void> hkdf_sha256(
    uint8_t* output, size_t output_len,
    const uint8_t* secret, size_t secret_len,
    const uint8_t* salt, size_t salt_len,
    const uint8_t* info, size_t info_len);

// Nonce utilities
inline Nonce make_nonce(uint64_t counter, bool big_endian = true) {
    Nonce nonce{};
    if (big_endian) {
        // Big-endian encoding (AES)
        nonce[4] = (counter >> 56) & 0xFF;
        nonce[5] = (counter >> 48) & 0xFF;
        nonce[6] = (counter >> 40) & 0xFF;
        nonce[7] = (counter >> 32) & 0xFF;
        nonce[8] = (counter >> 24) & 0xFF;
        nonce[9] = (counter >> 16) & 0xFF;
        nonce[10] = (counter >> 8) & 0xFF;
        nonce[11] = counter & 0xFF;
    } else {
        // Little-endian encoding (ChaCha20)
        nonce[4] = counter & 0xFF;
        nonce[5] = (counter >> 8) & 0xFF;
        nonce[6] = (counter >> 16) & 0xFF;
        nonce[7] = (counter >> 24) & 0xFF;
        nonce[8] = (counter >> 32) & 0xFF;
        nonce[9] = (counter >> 40) & 0xFF;
        nonce[10] = (counter >> 48) & 0xFF;
        nonce[11] = (counter >> 56) & 0xFF;
    }
    return nonce;
}

// Initialize crypto library
Result<void> init_crypto();

// Cleanup crypto library  
void cleanup_crypto();

} // namespace nebula