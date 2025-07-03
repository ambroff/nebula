#include "nebula/noise.hpp"
#include <cstring>
#include <algorithm>

namespace nebula {

namespace {

// Constants for Noise protocol
constexpr size_t NOISE_MAX_PAYLOAD_LEN = 65535;
constexpr size_t NOISE_TAG_LEN = 16;
constexpr size_t NOISE_KEY_LEN = 32;
constexpr size_t NOISE_HASH_LEN = 32;

// Protocol name components
const char* get_dh_name(CurveType curve) {
    switch (curve) {
        case CurveType::CURVE25519: return "25519";
        case CurveType::P256: return "P256";
        default: return "Unknown";
    }
}

const char* get_cipher_name(CipherType cipher) {
    switch (cipher) {
        case CipherType::AES256_GCM: return "AESGCM";
        case CipherType::CHACHA20_POLY1305: return "ChaChaPoly";
        default: return "Unknown";
    }
}

// HKDF with specific labels for Noise
Result<void> noise_hkdf(
    uint8_t* out1, size_t out1_len,
    uint8_t* out2, size_t out2_len,
    const uint8_t* chaining_key, size_t ck_len,
    const uint8_t* input_key, size_t input_len) {
    
    // First, compute temp_key = HMAC(chaining_key, input_key)
    auto temp_result = hmac_sha256(
        SymmetricKey{}, // Will be filled from chaining_key
        input_key, input_len);
    
    if (temp_result.is_error()) {
        return Result<void>(temp_result.error());
    }
    
    // Copy chaining_key to SymmetricKey for HMAC
    SymmetricKey ck_array{};
    std::memcpy(ck_array.data(), chaining_key, std::min(ck_len, size_t(32)));
    
    temp_result = hmac_sha256(ck_array, input_key, input_len);
    if (temp_result.is_error()) {
        return Result<void>(temp_result.error());
    }
    
    auto temp_key = temp_result.value();
    
    // out1 = HMAC(temp_key, 0x01)
    uint8_t one = 0x01;
    auto out1_result = hmac_sha256(temp_key, &one, 1);
    if (out1_result.is_error()) {
        return Result<void>(out1_result.error());
    }
    std::memcpy(out1, out1_result.value().data(), std::min(out1_len, size_t(32)));
    
    // out2 = HMAC(temp_key, out1 || 0x02)
    std::vector<uint8_t> out2_input(out1_len + 1);
    std::memcpy(out2_input.data(), out1, out1_len);
    out2_input[out1_len] = 0x02;
    
    auto out2_result = hmac_sha256(temp_key, out2_input.data(), out2_input.size());
    if (out2_result.is_error()) {
        return Result<void>(out2_result.error());
    }
    std::memcpy(out2, out2_result.value().data(), std::min(out2_len, size_t(32)));
    
    return Result<void>();
}

} // anonymous namespace

// CipherState implementation

Result<CipherState::Ptr> CipherState::create(CipherType cipher, const SymmetricKey& key) {
    auto aead_result = AEAD::create(cipher, key);
    if (aead_result.is_error()) {
        return Result<Ptr>(aead_result.error());
    }
    
    bool big_endian = (cipher == CipherType::AES256_GCM);
    return Result<Ptr>(std::unique_ptr<CipherState>(
        new CipherState(std::move(aead_result.value()), big_endian)));
}

CipherState::CipherState(std::unique_ptr<AEAD> aead, bool big_endian)
    : aead_(std::move(aead)), big_endian_(big_endian) {}

Result<std::vector<uint8_t>> CipherState::encrypt(
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* ad, size_t ad_len,
    uint64_t counter) {
    
    auto nonce = make_nonce(counter, big_endian_);
    return aead_->encrypt(plaintext, plaintext_len, ad, ad_len, nonce);
}

Result<std::vector<uint8_t>> CipherState::decrypt(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* ad, size_t ad_len,
    uint64_t counter) {
    
    auto nonce = make_nonce(counter, big_endian_);
    return aead_->decrypt(ciphertext, ciphertext_len, ad, ad_len, nonce);
}

// HandshakeState implementation

HandshakeState::HandshakeState(const Config& config) : config_(config) {}

Result<HandshakeState::Ptr> HandshakeState::create(const Config& config) {
    auto hs = std::unique_ptr<HandshakeState>(new HandshakeState(config));
    
    // Initialize with protocol name
    std::string protocol_name = hs->pattern_name();
    auto hash_result = sha256(
        reinterpret_cast<const uint8_t*>(protocol_name.data()),
        protocol_name.length());
    
    if (hash_result.is_error()) {
        return Result<Ptr>("Failed to hash protocol name: " + hash_result.error());
    }
    
    hs->handshake_hash_ = hash_result.value();
    hs->chaining_key_ = hash_result.value();
    
    // Mix in prologue if provided
    if (!config.prologue.empty()) {
        auto mix_result = hs->mix_hash(config.prologue.data(), config.prologue.size());
        if (mix_result.is_error()) {
            return Result<Ptr>("Failed to mix prologue: " + mix_result.error());
        }
    }
    
    // For IX pattern as responder, we need the initiator's static key
    if (config.pattern == NoisePattern::IX && 
        config.role == NoiseRole::Responder && 
        !config.remote_static.is_valid()) {
        // This will be set when we receive the first message
    }
    
    return Result<Ptr>(std::move(hs));
}

std::string HandshakeState::pattern_name() const {
    std::string name = "Noise_";
    
    switch (config_.pattern) {
        case NoisePattern::IX: name += "IX_"; break;
        case NoisePattern::XX: name += "XX_"; break;
    }
    
    name += get_dh_name(config_.curve);
    name += "_";
    name += get_cipher_name(config_.cipher);
    name += "_SHA256";
    
    return name;
}

Result<void> HandshakeState::mix_hash(const uint8_t* data, size_t len) {
    // h = HASH(h || data)
    std::vector<uint8_t> input(NOISE_HASH_LEN + len);
    std::memcpy(input.data(), handshake_hash_.data(), NOISE_HASH_LEN);
    std::memcpy(input.data() + NOISE_HASH_LEN, data, len);
    
    auto hash_result = sha256(input.data(), input.size());
    if (hash_result.is_error()) {
        return Result<void>(hash_result.error());
    }
    
    handshake_hash_ = hash_result.value();
    return Result<void>();
}

Result<void> HandshakeState::mix_key(const uint8_t* data, size_t len) {
    // Updates chaining_key and initializes cipher key
    SymmetricKey temp_key;
    auto hkdf_result = noise_hkdf(
        chaining_key_.data(), NOISE_KEY_LEN,
        temp_key.data(), NOISE_KEY_LEN,
        chaining_key_.data(), NOISE_KEY_LEN,
        data, len);
    
    if (hkdf_result.is_error()) {
        return hkdf_result;
    }
    
    // Create cipher with new key
    auto cipher_result = AEAD::create(config_.cipher, temp_key);
    if (cipher_result.is_error()) {
        return Result<void>(cipher_result.error());
    }
    
    cipher_ = std::move(cipher_result.value());
    has_key_ = true;
    
    return Result<void>();
}

Result<std::vector<uint8_t>> HandshakeState::encrypt_and_hash(
    const uint8_t* plaintext, size_t len) {
    
    if (!has_key_ || !cipher_) {
        // No key yet, just return plaintext and mix into hash
        std::vector<uint8_t> output(plaintext, plaintext + len);
        auto mix_result = mix_hash(plaintext, len);
        if (mix_result.is_error()) {
            return Result<std::vector<uint8_t>>(mix_result.error());
        }
        return output;
    }
    
    // Encrypt with handshake_hash as AD
    Nonce zero_nonce{};  // Always use zero nonce during handshake
    auto encrypt_result = cipher_->encrypt(
        plaintext, len,
        handshake_hash_.data(), NOISE_HASH_LEN,
        zero_nonce);
    
    if (encrypt_result.is_error()) {
        return encrypt_result;
    }
    
    // Mix ciphertext into hash
    auto ciphertext = encrypt_result.value();
    auto mix_result = mix_hash(ciphertext.data(), ciphertext.size());
    if (mix_result.is_error()) {
        return Result<std::vector<uint8_t>>(mix_result.error());
    }
    
    return ciphertext;
}

Result<std::vector<uint8_t>> HandshakeState::decrypt_and_hash(
    const uint8_t* ciphertext, size_t len) {
    
    if (!has_key_ || !cipher_) {
        // No key yet, just return ciphertext and mix into hash
        std::vector<uint8_t> output(ciphertext, ciphertext + len);
        auto mix_result = mix_hash(ciphertext, len);
        if (mix_result.is_error()) {
            return Result<std::vector<uint8_t>>(mix_result.error());
        }
        return output;
    }
    
    // Decrypt with handshake_hash as AD
    Nonce zero_nonce{};
    auto decrypt_result = cipher_->decrypt(
        ciphertext, len,
        handshake_hash_.data(), NOISE_HASH_LEN,
        zero_nonce);
    
    if (decrypt_result.is_error()) {
        return decrypt_result;
    }
    
    // Mix ciphertext into hash (before returning plaintext)
    auto mix_result = mix_hash(ciphertext, len);
    if (mix_result.is_error()) {
        return Result<std::vector<uint8_t>>(mix_result.error());
    }
    
    return decrypt_result;
}

Result<void> HandshakeState::write_e() {
    // Generate ephemeral keypair
    auto kp_result = generate_keypair(config_.curve);
    if (kp_result.is_error()) {
        return Result<void>("Failed to generate ephemeral key: " + kp_result.error());
    }
    
    auto kp = kp_result.value();
    ephemeral_key_ = kp.private_key;
    ephemeral_public_ = kp.public_key;
    
    // Mix ephemeral public key into hash
    return mix_hash(ephemeral_public_.bytes().data(), ephemeral_public_.bytes().size());
}

Result<void> HandshakeState::read_e(const uint8_t*& data, size_t& remaining) {
    size_t key_len = (config_.curve == CurveType::CURVE25519) ? 32 : 65; // P256 uses uncompressed
    
    if (remaining < key_len) {
        return Result<void>("Message too short for ephemeral key");
    }
    
    std::vector<uint8_t> key_bytes(data, data + key_len);
    remote_ephemeral_ = PublicKey(key_bytes, config_.curve);
    
    data += key_len;
    remaining -= key_len;
    
    // Mix remote ephemeral into hash
    return mix_hash(key_bytes.data(), key_bytes.size());
}

Result<void> HandshakeState::write_s() {
    // Encrypt and write static public key
    auto encrypted = encrypt_and_hash(
        config_.static_public.bytes().data(),
        config_.static_public.bytes().size());
    
    if (encrypted.is_error()) {
        return Result<void>("Failed to encrypt static key: " + encrypted.error());
    }
    
    // Note: The encrypted data is returned to the caller via write_message
    return Result<void>();
}

Result<void> HandshakeState::read_s(const uint8_t*& data, size_t& remaining) {
    size_t key_len = (config_.curve == CurveType::CURVE25519) ? 32 : 65;
    size_t encrypted_len = has_key_ ? (key_len + NOISE_TAG_LEN) : key_len;
    
    if (remaining < encrypted_len) {
        return Result<void>("Message too short for static key");
    }
    
    // Decrypt static key
    auto decrypted = decrypt_and_hash(data, encrypted_len);
    if (decrypted.is_error()) {
        return Result<void>("Failed to decrypt static key: " + decrypted.error());
    }
    
    if (decrypted.value().size() != key_len) {
        return Result<void>("Invalid static key length");
    }
    
    remote_static_ = PublicKey(decrypted.value(), config_.curve);
    
    data += encrypted_len;
    remaining -= encrypted_len;
    
    return Result<void>();
}

Result<void> HandshakeState::dh_ee() {
    if (!ephemeral_key_ || !remote_ephemeral_.is_valid()) {
        return Result<void>("Missing ephemeral keys for DH");
    }
    
    auto shared_result = ephemeral_key_->ecdh(remote_ephemeral_);
    if (shared_result.is_error()) {
        return Result<void>("DH ee failed: " + shared_result.error());
    }
    
    return mix_key(shared_result.value().data(), shared_result.value().size());
}

Result<void> HandshakeState::dh_es() {
    if (config_.role == NoiseRole::Initiator) {
        // Initiator: DH(e, rs)
        if (!ephemeral_key_ || !remote_static_.is_valid()) {
            return Result<void>("Missing keys for DH es");
        }
        
        auto shared_result = ephemeral_key_->ecdh(remote_static_);
        if (shared_result.is_error()) {
            return Result<void>("DH es failed: " + shared_result.error());
        }
        
        return mix_key(shared_result.value().data(), shared_result.value().size());
    } else {
        // Responder: DH(s, re)
        if (!config_.static_key || !remote_ephemeral_.is_valid()) {
            return Result<void>("Missing keys for DH es");
        }
        
        auto shared_result = config_.static_key->ecdh(remote_ephemeral_);
        if (shared_result.is_error()) {
            return Result<void>("DH es failed: " + shared_result.error());
        }
        
        return mix_key(shared_result.value().data(), shared_result.value().size());
    }
}

Result<void> HandshakeState::dh_se() {
    if (config_.role == NoiseRole::Initiator) {
        // Initiator: DH(s, re)
        if (!config_.static_key || !remote_ephemeral_.is_valid()) {
            return Result<void>("Missing keys for DH se");
        }
        
        auto shared_result = config_.static_key->ecdh(remote_ephemeral_);
        if (shared_result.is_error()) {
            return Result<void>("DH se failed: " + shared_result.error());
        }
        
        return mix_key(shared_result.value().data(), shared_result.value().size());
    } else {
        // Responder: DH(e, rs)
        if (!ephemeral_key_ || !remote_static_.is_valid()) {
            return Result<void>("Missing keys for DH se");
        }
        
        auto shared_result = ephemeral_key_->ecdh(remote_static_);
        if (shared_result.is_error()) {
            return Result<void>("DH se failed: " + shared_result.error());
        }
        
        return mix_key(shared_result.value().data(), shared_result.value().size());
    }
}

Result<std::pair<SymmetricKey, SymmetricKey>> HandshakeState::split() {
    // Generate two keys from the current state
    SymmetricKey k1, k2;
    
    auto hkdf_result = noise_hkdf(
        k1.data(), NOISE_KEY_LEN,
        k2.data(), NOISE_KEY_LEN,
        chaining_key_.data(), NOISE_KEY_LEN,
        nullptr, 0);  // Empty input
    
    if (hkdf_result.is_error()) {
        return Result<std::pair<SymmetricKey, SymmetricKey>>(hkdf_result.error());
    }
    
    // In Noise, initiator uses k1 for sending, k2 for receiving
    // Responder uses k2 for sending, k1 for receiving
    if (config_.role == NoiseRole::Initiator) {
        return std::make_pair(k1, k2);  // send, recv
    } else {
        return std::make_pair(k2, k1);  // send, recv
    }
}

Result<HandshakeState::HandshakeResult> HandshakeState::write_message(
    const uint8_t* payload, size_t payload_len) {
    
    if (handshake_complete_) {
        return Result<HandshakeResult>("Handshake already complete");
    }
    
    HandshakeResult result;
    std::vector<uint8_t> message;
    
    // IX pattern message patterns:
    // -> e, s
    // <- e, ee, se, s, es
    
    if (config_.role == NoiseRole::Initiator) {
        if (message_index_ == 0) {
            // First message: e, s
            // Write ephemeral key
            auto e_result = write_e();
            if (e_result.is_error()) {
                return Result<HandshakeResult>(e_result.error());
            }
            
            // Append ephemeral public key
            const auto& e_bytes = ephemeral_public_.bytes();
            message.insert(message.end(), e_bytes.begin(), e_bytes.end());
            
            // Write and encrypt static key
            auto s_encrypted = encrypt_and_hash(
                config_.static_public.bytes().data(),
                config_.static_public.bytes().size());
            if (s_encrypted.is_error()) {
                return Result<HandshakeResult>(s_encrypted.error());
            }
            
            // Append encrypted static key
            message.insert(message.end(), 
                          s_encrypted.value().begin(), 
                          s_encrypted.value().end());
            
            // Encrypt payload
            auto payload_encrypted = encrypt_and_hash(payload, payload_len);
            if (payload_encrypted.is_error()) {
                return Result<HandshakeResult>(payload_encrypted.error());
            }
            
            // Append encrypted payload
            message.insert(message.end(),
                          payload_encrypted.value().begin(),
                          payload_encrypted.value().end());
            
            message_index_++;
            result.output = std::move(message);
            result.handshake_complete = false;
            
        } else {
            return Result<HandshakeResult>("Invalid message index for initiator");
        }
        
    } else {
        // Responder
        if (message_index_ == 1) {
            // Second message: e, ee, se, s, es
            // Write ephemeral key
            auto e_result = write_e();
            if (e_result.is_error()) {
                return Result<HandshakeResult>(e_result.error());
            }
            
            // Append ephemeral public key
            const auto& e_bytes = ephemeral_public_.bytes();
            message.insert(message.end(), e_bytes.begin(), e_bytes.end());
            
            // DH ee
            auto ee_result = dh_ee();
            if (ee_result.is_error()) {
                return Result<HandshakeResult>(ee_result.error());
            }
            
            // DH se
            auto se_result = dh_se();
            if (se_result.is_error()) {
                return Result<HandshakeResult>(se_result.error());
            }
            
            // Write and encrypt static key
            auto s_encrypted = encrypt_and_hash(
                config_.static_public.bytes().data(),
                config_.static_public.bytes().size());
            if (s_encrypted.is_error()) {
                return Result<HandshakeResult>(s_encrypted.error());
            }
            
            // Append encrypted static key
            message.insert(message.end(),
                          s_encrypted.value().begin(),
                          s_encrypted.value().end());
            
            // DH es
            auto es_result = dh_es();
            if (es_result.is_error()) {
                return Result<HandshakeResult>(es_result.error());
            }
            
            // Encrypt payload
            auto payload_encrypted = encrypt_and_hash(payload, payload_len);
            if (payload_encrypted.is_error()) {
                return Result<HandshakeResult>(payload_encrypted.error());
            }
            
            // Append encrypted payload
            message.insert(message.end(),
                          payload_encrypted.value().begin(),
                          payload_encrypted.value().end());
            
            // Split for transport keys
            auto split_result = split();
            if (split_result.is_error()) {
                return Result<HandshakeResult>(split_result.error());
            }
            
            message_index_++;
            handshake_complete_ = true;
            
            result.output = std::move(message);
            result.transport_keys = split_result.value();
            result.handshake_complete = true;
            
        } else {
            return Result<HandshakeResult>("Invalid message index for responder");
        }
    }
    
    return result;
}

Result<HandshakeState::HandshakeResult> HandshakeState::read_message(
    const uint8_t* message, size_t message_len) {
    
    if (handshake_complete_) {
        return Result<HandshakeResult>("Handshake already complete");
    }
    
    HandshakeResult result;
    const uint8_t* data = message;
    size_t remaining = message_len;
    
    if (config_.role == NoiseRole::Initiator) {
        if (message_index_ == 1) {
            // Read second message: e, ee, se, s, es
            // Read remote ephemeral
            auto e_result = read_e(data, remaining);
            if (e_result.is_error()) {
                return Result<HandshakeResult>(e_result.error());
            }
            
            // DH ee
            auto ee_result = dh_ee();
            if (ee_result.is_error()) {
                return Result<HandshakeResult>(ee_result.error());
            }
            
            // DH se
            auto se_result = dh_se();
            if (se_result.is_error()) {
                return Result<HandshakeResult>(se_result.error());
            }
            
            // Read remote static
            auto s_result = read_s(data, remaining);
            if (s_result.is_error()) {
                return Result<HandshakeResult>(s_result.error());
            }
            
            // DH es
            auto es_result = dh_es();
            if (es_result.is_error()) {
                return Result<HandshakeResult>(es_result.error());
            }
            
            // Decrypt payload
            if (remaining > 0) {
                auto payload_decrypted = decrypt_and_hash(data, remaining);
                if (payload_decrypted.is_error()) {
                    return Result<HandshakeResult>(payload_decrypted.error());
                }
                result.output = payload_decrypted.value();
            }
            
            // Split for transport keys
            auto split_result = split();
            if (split_result.is_error()) {
                return Result<HandshakeResult>(split_result.error());
            }
            
            message_index_++;
            handshake_complete_ = true;
            
            result.transport_keys = split_result.value();
            result.handshake_complete = true;
            
        } else {
            return Result<HandshakeResult>("Invalid message index for initiator");
        }
        
    } else {
        // Responder
        if (message_index_ == 0) {
            // Read first message: e, s
            // Read remote ephemeral
            auto e_result = read_e(data, remaining);
            if (e_result.is_error()) {
                return Result<HandshakeResult>(e_result.error());
            }
            
            // Read remote static
            auto s_result = read_s(data, remaining);
            if (s_result.is_error()) {
                return Result<HandshakeResult>(s_result.error());
            }
            
            // Decrypt payload
            if (remaining > 0) {
                auto payload_decrypted = decrypt_and_hash(data, remaining);
                if (payload_decrypted.is_error()) {
                    return Result<HandshakeResult>(payload_decrypted.error());
                }
                result.output = payload_decrypted.value();
            }
            
            message_index_++;
            result.handshake_complete = false;
            
        } else {
            return Result<HandshakeResult>("Invalid message index for responder");
        }
    }
    
    return result;
}

// ConnectionState implementation

ConnectionState::ConnectionState(
    std::unique_ptr<CipherState> send_cipher,
    std::unique_ptr<CipherState> recv_cipher,
    bool initiator)
    : send_cipher_(std::move(send_cipher))
    , recv_cipher_(std::move(recv_cipher))
    , initiator_(initiator) {}

Result<std::vector<uint8_t>> ConnectionState::encrypt(
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* header, size_t header_len,
    MessageCounter counter) {
    
    return send_cipher_->encrypt(plaintext, plaintext_len, header, header_len, counter);
}

Result<std::vector<uint8_t>> ConnectionState::decrypt(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* header, size_t header_len,
    MessageCounter counter) {
    
    return recv_cipher_->decrypt(ciphertext, ciphertext_len, header, header_len, counter);
}

} // namespace nebula