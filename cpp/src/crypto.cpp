#include "nebula/crypto.hpp"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <iomanip>
#include <sstream>
#include <cstring>

namespace nebula {

namespace {

// Get OpenSSL error string
std::string get_openssl_error() {
    unsigned long err = ERR_get_error();
    if (err == 0) {
        return "Unknown OpenSSL error";
    }
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

// RAII wrapper for EVP contexts
struct EVPContextDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const { EVP_CIPHER_CTX_free(ctx); }
    void operator()(EVP_MD_CTX* ctx) const { EVP_MD_CTX_free(ctx); }
    void operator()(EVP_PKEY_CTX* ctx) const { EVP_PKEY_CTX_free(ctx); }
    void operator()(EVP_PKEY* key) const { EVP_PKEY_free(key); }
    void operator()(EVP_MAC* mac) const { EVP_MAC_free(mac); }
    void operator()(EVP_MAC_CTX* ctx) const { EVP_MAC_CTX_free(ctx); }
    void operator()(EVP_KDF* kdf) const { EVP_KDF_free(kdf); }
    void operator()(EVP_KDF_CTX* ctx) const { EVP_KDF_CTX_free(ctx); }
};

using EVPCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EVPContextDeleter>;
using EVPPKeyPtr = std::unique_ptr<EVP_PKEY, EVPContextDeleter>;
using EVPPKeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EVPContextDeleter>;

// Curve25519 private key implementation
class Curve25519PrivateKey : public PrivateKey {
public:
    explicit Curve25519PrivateKey(EVPPKeyPtr key) : key_(std::move(key)) {}
    
    Result<SymmetricKey> ecdh(const PublicKey& peer_public) const override {
        if (peer_public.curve() != CurveType::CURVE25519) {
            return Result<SymmetricKey>("Curve mismatch");
        }
        
        // Create peer public key
        EVPPKeyPtr peer_key(EVP_PKEY_new_raw_public_key(
            EVP_PKEY_X25519, nullptr,
            peer_public.bytes().data(), peer_public.bytes().size()));
        
        if (!peer_key) {
            return Result<SymmetricKey>("Failed to create peer key: " + get_openssl_error());
        }
        
        // Create derivation context
        EVPPKeyCtxPtr ctx(EVP_PKEY_CTX_new(key_.get(), nullptr));
        if (!ctx) {
            return Result<SymmetricKey>("Failed to create context: " + get_openssl_error());
        }
        
        if (EVP_PKEY_derive_init(ctx.get()) <= 0) {
            return Result<SymmetricKey>("Failed to init derive: " + get_openssl_error());
        }
        
        if (EVP_PKEY_derive_set_peer(ctx.get(), peer_key.get()) <= 0) {
            return Result<SymmetricKey>("Failed to set peer: " + get_openssl_error());
        }
        
        // Derive shared secret
        SymmetricKey shared;
        size_t shared_len = shared.size();
        
        if (EVP_PKEY_derive(ctx.get(), shared.data(), &shared_len) <= 0) {
            return Result<SymmetricKey>("Failed to derive key: " + get_openssl_error());
        }
        
        if (shared_len != 32) {
            return Result<SymmetricKey>("Invalid derived key length");
        }
        
        return shared;
    }
    
    PublicKey public_key() const override {
        size_t len = 32;
        std::vector<uint8_t> pub(len);
        
        if (EVP_PKEY_get_raw_public_key(key_.get(), pub.data(), &len) != 1) {
            return PublicKey();
        }
        
        pub.resize(len);
        return PublicKey(pub, CurveType::CURVE25519);
    }
    
    CurveType curve() const override {
        return CurveType::CURVE25519;
    }
    
    std::vector<uint8_t> export_key() const override {
        size_t len = 32;
        std::vector<uint8_t> priv(len);
        
        if (EVP_PKEY_get_raw_private_key(key_.get(), priv.data(), &len) != 1) {
            return {};
        }
        
        priv.resize(len);
        return priv;
    }
    
private:
    EVPPKeyPtr key_;
};

// AES-GCM implementation
class AES_GCM : public AEAD {
public:
    explicit AES_GCM(const SymmetricKey& key) : key_(key) {}
    
    Result<std::vector<uint8_t>> encrypt(
        const uint8_t* plaintext, size_t len,
        const uint8_t* additional_data, size_t ad_len,
        const Nonce& nonce) override {
        
        std::vector<uint8_t> output(len + GCM_TAG_SIZE);
        std::memcpy(output.data(), plaintext, len);
        
        auto encrypt_res = encrypt_in_place(output.data(), len, output.size(),
                                          additional_data, ad_len, nonce);
        
        if (encrypt_res.is_error()) {
            return Result<std::vector<uint8_t>>(encrypt_res.error());
        }
        
        size_t out_len = encrypt_res.value();
        output.resize(out_len);
        return output;
    }
    
    Result<std::vector<uint8_t>> decrypt(
        const uint8_t* ciphertext, size_t len,
        const uint8_t* additional_data, size_t ad_len,
        const Nonce& nonce) override {
        
        if (len < GCM_TAG_SIZE) {
            return Result<std::vector<uint8_t>>("Ciphertext too short");
        }
        
        std::vector<uint8_t> output(len);
        std::memcpy(output.data(), ciphertext, len);
        
        auto decrypt_res = decrypt_in_place(output.data(), len,
                                          additional_data, ad_len, nonce);
        
        if (decrypt_res.is_error()) {
            return Result<std::vector<uint8_t>>(decrypt_res.error());
        }
        
        size_t out_len = decrypt_res.value();
        
        output.resize(out_len);
        return output;
    }
    
    size_t overhead() const override {
        return GCM_TAG_SIZE;
    }
    
    Result<size_t> encrypt_in_place(
        uint8_t* data, size_t len, size_t max_len,
        const uint8_t* additional_data, size_t ad_len,
        const Nonce& nonce) override {
        
        if (max_len < len + GCM_TAG_SIZE) {
            return Result<size_t>("Buffer too small");
        }
        
        EVPCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
        if (!ctx) {
            return Result<size_t>("Failed to create context");
        }
        
        if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            return Result<size_t>("Failed to init cipher");
        }
        
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr) != 1) {
            return Result<size_t>("Failed to set nonce length");
        }
        
        if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key_.data(), nonce.data()) != 1) {
            return Result<size_t>("Failed to set key and nonce");
        }
        
        if (ad_len > 0 && additional_data != nullptr) {
            int out_len;
            if (EVP_EncryptUpdate(ctx.get(), nullptr, &out_len, additional_data, ad_len) != 1) {
                return Result<size_t>("Failed to set additional data");
            }
        }
        
        int out_len;
        if (EVP_EncryptUpdate(ctx.get(), data, &out_len, data, len) != 1) {
            return Result<size_t>("Failed to encrypt");
        }
        
        int final_len;
        if (EVP_EncryptFinal_ex(ctx.get(), data + out_len, &final_len) != 1) {
            return Result<size_t>("Failed to finalize");
        }
        
        // Get tag
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, 
                               data + len) != 1) {
            return Result<size_t>("Failed to get tag");
        }
        
        return Result<size_t>(len + GCM_TAG_SIZE);
    }
    
    Result<size_t> decrypt_in_place(
        uint8_t* data, size_t len,
        const uint8_t* additional_data, size_t ad_len,
        const Nonce& nonce) override {
        
        if (len < GCM_TAG_SIZE) {
            return Result<size_t>("Ciphertext too short");
        }
        
        size_t ciphertext_len = len - GCM_TAG_SIZE;
        
        EVPCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
        if (!ctx) {
            return Result<size_t>("Failed to create context");
        }
        
        if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            return Result<size_t>("Failed to init cipher");
        }
        
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr) != 1) {
            return Result<size_t>("Failed to set nonce length");
        }
        
        if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key_.data(), nonce.data()) != 1) {
            return Result<size_t>("Failed to set key and nonce");
        }
        
        if (ad_len > 0 && additional_data != nullptr) {
            int out_len;
            if (EVP_DecryptUpdate(ctx.get(), nullptr, &out_len, additional_data, ad_len) != 1) {
                return Result<size_t>("Failed to set additional data");
            }
        }
        
        int out_len;
        if (EVP_DecryptUpdate(ctx.get(), data, &out_len, data, ciphertext_len) != 1) {
            return Result<size_t>("Failed to decrypt");
        }
        
        // Set tag
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE,
                               data + ciphertext_len) != 1) {
            return Result<size_t>("Failed to set tag");
        }
        
        int final_len;
        if (EVP_DecryptFinal_ex(ctx.get(), data + out_len, &final_len) != 1) {
            return Result<size_t>("Authentication failed");
        }
        
        return Result<size_t>(out_len + final_len);
    }
    
private:
    SymmetricKey key_;
};

} // anonymous namespace

// PublicKey implementation
PublicKey::PublicKey(const std::vector<uint8_t>& data, CurveType curve)
    : data_(data), curve_(curve) {}

std::string PublicKey::to_hex() const {
    std::stringstream ss;
    for (uint8_t byte : data_) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return ss.str();
}

Result<PublicKey> PublicKey::from_hex(const std::string& hex, CurveType curve) {
    if (hex.length() % 2 != 0) {
        return Result<PublicKey>("Invalid hex length");
    }
    
    std::vector<uint8_t> data;
    data.reserve(hex.length() / 2);
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        try {
            uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
            data.push_back(byte);
        } catch (...) {
            return Result<PublicKey>("Invalid hex string");
        }
    }
    
    return PublicKey(data, curve);
}

// Key generation
Result<DHResult> generate_keypair(CurveType curve) {
    if (curve == CurveType::CURVE25519) {
        EVPPKeyPtr key(EVP_PKEY_new());
        EVPPKeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr));
        
        if (!ctx) {
            return Result<DHResult>("Failed to create context: " + get_openssl_error());
        }
        
        if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
            return Result<DHResult>("Failed to init keygen: " + get_openssl_error());
        }
        
        EVP_PKEY* raw_key = nullptr;
        if (EVP_PKEY_keygen(ctx.get(), &raw_key) <= 0) {
            return Result<DHResult>("Failed to generate key: " + get_openssl_error());
        }
        
        key.reset(raw_key);
        
        auto priv = std::make_shared<Curve25519PrivateKey>(std::move(key));
        DHResult result;
        result.private_key = priv;
        result.public_key = priv->public_key();
        
        return result;
    }
    
    return Result<DHResult>("Unsupported curve");
}

// Private key import
Result<std::shared_ptr<PrivateKey>> PrivateKey::import_key(
    const std::vector<uint8_t>& data, CurveType curve) {
    
    if (curve == CurveType::CURVE25519) {
        if (data.size() != 32) {
            return Result<std::shared_ptr<PrivateKey>>("Invalid key size");
        }
        
        EVPPKeyPtr key(EVP_PKEY_new_raw_private_key(
            EVP_PKEY_X25519, nullptr, data.data(), data.size()));
        
        if (!key) {
            return Result<std::shared_ptr<PrivateKey>>(
                "Failed to import key: " + get_openssl_error());
        }
        
        return Result<std::shared_ptr<PrivateKey>>(
            std::static_pointer_cast<PrivateKey>(
                std::make_shared<Curve25519PrivateKey>(std::move(key))
            )
        );
    }
    
    return Result<std::shared_ptr<PrivateKey>>("Unsupported curve");
}

// AEAD factory
Result<AEAD::Ptr> AEAD::create(CipherType cipher, const SymmetricKey& key) {
    switch (cipher) {
        case CipherType::AES256_GCM:
            return Result<Ptr>(std::make_unique<AES_GCM>(key));
            
        case CipherType::CHACHA20_POLY1305:
            // TODO: Implement ChaCha20-Poly1305
            return Result<Ptr>("ChaCha20-Poly1305 not implemented yet");
            
        default:
            return Result<Ptr>("Unknown cipher type");
    }
}

// Hash functions
Result<Hash> sha256(const uint8_t* data, size_t len) {
    Hash hash;
    if (SHA256(data, len, hash.data()) == nullptr) {
        return Result<Hash>("SHA256 failed");
    }
    return hash;
}

Result<Hash> sha256(const std::vector<uint8_t>& data) {
    return sha256(data.data(), data.size());
}

// HMAC
Result<Hash> hmac_sha256(const SymmetricKey& key, const uint8_t* data, size_t len) {
    Hash mac;
    unsigned int mac_len = mac.size();
    
    if (HMAC(EVP_sha256(), key.data(), key.size(), data, len, 
             mac.data(), &mac_len) == nullptr) {
        return Result<Hash>("HMAC failed");
    }
    
    if (mac_len != SHA256_HASH_SIZE) {
        return Result<Hash>("Invalid HMAC length");
    }
    
    return mac;
}

// Random bytes
Result<void> random_bytes(uint8_t* out, size_t len) {
    if (RAND_bytes(out, len) != 1) {
        return Result<void>("Failed to generate random bytes");
    }
    return Result<void>();
}

Result<std::vector<uint8_t>> random_bytes(size_t len) {
    std::vector<uint8_t> data(len);
    auto result = random_bytes(data.data(), len);
    if (result.is_error()) {
        return Result<std::vector<uint8_t>>(result.error());
    }
    return data;
}

// HKDF
Result<void> hkdf_sha256(
    uint8_t* output, size_t output_len,
    const uint8_t* secret, size_t secret_len,
    const uint8_t* salt, size_t salt_len,
    const uint8_t* info, size_t info_len) {
    
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) {
        return Result<void>("Failed to fetch HKDF");
    }
    
    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    
    if (!ctx) {
        return Result<void>("Failed to create HKDF context");
    }
    
    OSSL_PARAM params[5];
    int n = 0;
    
    params[n++] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, const_cast<char*>("SHA256"), 0);
    params[n++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, const_cast<uint8_t*>(secret), secret_len);
    
    if (salt && salt_len > 0) {
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, const_cast<uint8_t*>(salt), salt_len);
    }
    
    if (info && info_len > 0) {
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO, const_cast<uint8_t*>(info), info_len);
    }
    
    params[n] = OSSL_PARAM_construct_end();
    
    if (EVP_KDF_derive(ctx, output, output_len, params) <= 0) {
        EVP_KDF_CTX_free(ctx);
        return Result<void>("HKDF derivation failed");
    }
    
    EVP_KDF_CTX_free(ctx);
    return Result<void>();
}

// Initialize crypto
Result<void> init_crypto() {
    // OpenSSL 3.0+ doesn't require explicit initialization
    return Result<void>();
}

// Cleanup crypto
void cleanup_crypto() {
    // OpenSSL 3.0+ handles cleanup automatically
}

} // namespace nebula