#pragma once

#include "types.hpp"
#include "crypto.hpp"
#include <string>
#include <vector>
#include <chrono>
#include <memory>
#include <set>
#include <map>

namespace nebula {

// Certificate versions
enum class CertVersion : uint8_t {
    Pre1 = 0,
    V1 = 1,
    V2 = 2
};

// Certificate curves (matches protobuf enum)
enum class CertCurve : int32_t {
    CURVE25519 = 0,
    P256 = 1
};

// Convert between cert curve and crypto curve types
inline CurveType cert_curve_to_crypto(CertCurve curve) {
    switch (curve) {
        case CertCurve::CURVE25519: return CurveType::CURVE25519;
        case CertCurve::P256: return CurveType::P256;
        default: throw std::runtime_error("Unknown curve");
    }
}

// Forward declarations
class Certificate;
class CertificateAuthority;

// Certificate interface
class Certificate {
public:
    using Ptr = std::shared_ptr<Certificate>;
    
    virtual ~Certificate() = default;
    
    // Version of this certificate
    virtual CertVersion version() const = 0;
    
    // Human-readable name
    virtual std::string name() const = 0;
    
    // Networks assigned to this certificate
    virtual std::vector<IpNet> networks() const = 0;
    
    // Unsafe networks this host can route
    virtual std::vector<IpNet> unsafe_networks() const = 0;
    
    // Groups for firewall rules
    virtual std::vector<std::string> groups() const = 0;
    
    // Check if this is a CA certificate
    virtual bool is_ca() const = 0;
    
    // Validity period
    virtual std::chrono::system_clock::time_point not_before() const = 0;
    virtual std::chrono::system_clock::time_point not_after() const = 0;
    
    // Issuer fingerprint (empty for CA certs)
    virtual std::string issuer() const = 0;
    
    // Public key
    virtual PublicKey public_key() const = 0;
    
    // Curve used
    virtual CertCurve curve() const = 0;
    
    // Signature
    virtual std::vector<uint8_t> signature() const = 0;
    
    // Verify signature using CA's public key
    virtual bool verify_signature(const PublicKey& ca_public_key) const = 0;
    
    // Get SHA256 fingerprint
    virtual std::string fingerprint() const = 0;
    
    // Check if expired at given time
    virtual bool is_expired(std::chrono::system_clock::time_point t) const = 0;
    
    // Check if valid at current time
    bool is_expired() const {
        return is_expired(std::chrono::system_clock::now());
    }
    
    // Verify private key matches
    virtual Result<void> verify_private_key(const PrivateKey& key) const = 0;
    
    // Marshal to wire format
    virtual Result<std::vector<uint8_t>> marshal() const = 0;
    
    // Marshal for handshakes (may differ from marshal)
    virtual Result<std::vector<uint8_t>> marshal_for_handshakes() const = 0;
    
    // Marshal to PEM format
    virtual Result<std::string> marshal_pem() const = 0;
    
    // String representation
    virtual std::string to_string() const = 0;
    
    // Check if a VPN IP is allowed by this certificate
    bool contains_ip(VpnIp ip) const;
    
    // Load from PEM string
    static Result<Ptr> from_pem(const std::string& pem);
    
    // Load from wire format bytes
    static Result<Ptr> unmarshal(const std::vector<uint8_t>& data);
    static Result<Ptr> unmarshal(const uint8_t* data, size_t len);
};

// Certificate Authority
class CertificateAuthority {
public:
    using Ptr = std::shared_ptr<CertificateAuthority>;
    
    // Create from CA certificate
    static Result<Ptr> create(Certificate::Ptr ca_cert);
    
    // Add a CA certificate to the pool
    Result<void> add_ca(Certificate::Ptr ca_cert);
    
    // Get CA certificate by fingerprint
    Certificate::Ptr get_ca(const std::string& fingerprint) const;
    
    // Verify a certificate is signed by a CA in this pool
    Result<Certificate::Ptr> verify_certificate(Certificate::Ptr cert) const;
    
    // Check if any CA is expired
    bool has_expired_ca() const;
    
    // Get all CA fingerprints
    std::vector<std::string> get_fingerprints() const;
    
    // Get blocklisted certificate fingerprints
    const std::set<std::string>& get_blocklist() const { return blocklist_; }
    
    // Add certificate to blocklist
    void add_to_blocklist(const std::string& fingerprint) {
        blocklist_.insert(fingerprint);
    }
    
    // Check if certificate is blocklisted
    bool is_blocklisted(const std::string& fingerprint) const {
        return blocklist_.find(fingerprint) != blocklist_.end();
    }
    
private:
    std::map<std::string, Certificate::Ptr> ca_certs_;  // fingerprint -> cert
    std::set<std::string> blocklist_;  // blocklisted fingerprints
};

// Certificate validation
class CertificateValidator {
public:
    // Validate certificate constraints
    static Result<void> validate_constraints(
        const Certificate& cert,
        const Certificate& ca_cert);
    
    // Check if cert networks are within CA networks
    static bool networks_contain(
        const std::vector<IpNet>& ca_networks,
        const std::vector<IpNet>& cert_networks);
    
    // Check if cert groups are allowed by CA
    static bool groups_contain(
        const std::vector<std::string>& ca_groups,
        const std::vector<std::string>& cert_groups);
};

// PEM constants
constexpr const char* NEBULA_CERT_BANNER = "NEBULA CERTIFICATE";
constexpr const char* NEBULA_KEY_BANNER = "NEBULA ED25519 PRIVATE KEY";
constexpr const char* NEBULA_X25519_KEY_BANNER = "NEBULA X25519 PRIVATE KEY";
constexpr const char* NEBULA_P256_KEY_BANNER = "NEBULA P256 PRIVATE KEY";
constexpr const char* NEBULA_ENCRYPTED_KEY_BANNER = "NEBULA ENCRYPTED PRIVATE KEY";

} // namespace nebula