#include "nebula/cert.hpp"
#include "cert_v1.pb.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace nebula {

// Convert protobuf curve to our curve type
static CertCurve proto_curve_to_cert(cert::Curve curve) {
    switch (curve) {
        case cert::Curve::CURVE25519: return CertCurve::CURVE25519;
        case cert::Curve::P256: return CertCurve::P256;
        default: throw std::runtime_error("Unknown curve");
    }
}

// Certificate V1 implementation
class CertificateV1 : public Certificate {
public:
    CertificateV1() = default;
    
    // Parse from protobuf
    Result<void> parse(const cert::RawNebulaCertificate& raw) {
        if (!raw.has_details()) {
            return Result<void>("Certificate missing details");
        }
        
        const auto& details = raw.details();
        
        // Basic fields
        name_ = details.name();
        is_ca_ = details.isca();
        
        // Time fields
        not_before_ = std::chrono::system_clock::from_time_t(details.notbefore());
        not_after_ = std::chrono::system_clock::from_time_t(details.notafter());
        
        // Public key
        public_key_ = PublicKey(
            std::vector<uint8_t>(details.publickey().begin(), details.publickey().end()),
            cert_curve_to_crypto(proto_curve_to_cert(details.curve())));
        
        curve_ = proto_curve_to_cert(details.curve());
        
        // Issuer (SHA256 fingerprint)
        if (details.issuer().size() > 0) {
            // Convert bytes to hex string
            std::stringstream ss;
            for (uint8_t byte : details.issuer()) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
            }
            issuer_ = ss.str();
        }
        
        // Networks - stored as pairs of uint32 (ip, mask)
        for (int i = 0; i < details.ips_size(); i += 2) {
            if (i + 1 < details.ips_size()) {
                VpnIp ip = htonl(details.ips(i));
                uint32_t mask_bits = details.ips(i + 1);
                if (mask_bits > 32) {
                    return Result<void>("Invalid network mask");
                }
                networks_.emplace_back(ip, mask_bits);
            }
        }
        
        // Unsafe networks
        for (int i = 0; i < details.subnets_size(); i += 2) {
            if (i + 1 < details.subnets_size()) {
                VpnIp ip = htonl(details.subnets(i));
                uint32_t mask_bits = details.subnets(i + 1);
                if (mask_bits > 32) {
                    return Result<void>("Invalid subnet mask");
                }
                unsafe_networks_.emplace_back(ip, mask_bits);
            }
        }
        
        // Groups
        for (const auto& group : details.groups()) {
            groups_.push_back(group);
        }
        
        // Signature
        signature_.assign(raw.signature().begin(), raw.signature().end());
        
        // Store raw bytes for fingerprint calculation
        raw_details_ = details.SerializeAsString();
        
        return Result<void>();
    }
    
    CertVersion version() const override { return CertVersion::V1; }
    std::string name() const override { return name_; }
    std::vector<IpNet> networks() const override { return networks_; }
    std::vector<IpNet> unsafe_networks() const override { return unsafe_networks_; }
    std::vector<std::string> groups() const override { return groups_; }
    bool is_ca() const override { return is_ca_; }
    std::chrono::system_clock::time_point not_before() const override { return not_before_; }
    std::chrono::system_clock::time_point not_after() const override { return not_after_; }
    std::string issuer() const override { return issuer_; }
    PublicKey public_key() const override { return public_key_; }
    CertCurve curve() const override { return curve_; }
    std::vector<uint8_t> signature() const override { return signature_; }
    
    bool verify_signature(const PublicKey& ca_public_key) const override {
        if (ca_public_key.curve() != cert_curve_to_crypto(curve_)) {
            return false;
        }
        
        // For Ed25519 signatures
        if (curve_ == CertCurve::CURVE25519) {
            if (ca_public_key.bytes().size() != 32 || signature_.size() != 64) {
                return false;
            }
            
            // Use EVP API for Ed25519 verification
            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            if (!ctx) return false;
            
            EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
                EVP_PKEY_ED25519, nullptr,
                ca_public_key.bytes().data(),
                ca_public_key.bytes().size());
            
            if (!pkey) {
                EVP_MD_CTX_free(ctx);
                return false;
            }
            
            int result = EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey);
            if (result == 1) {
                result = EVP_DigestVerify(ctx, signature_.data(), signature_.size(),
                                        reinterpret_cast<const uint8_t*>(raw_details_.data()),
                                        raw_details_.size());
            }
            
            EVP_PKEY_free(pkey);
            EVP_MD_CTX_free(ctx);
            
            return result == 1;
        }
        
        // TODO: P256 signature verification
        return false;
    }
    
    std::string fingerprint() const override {
        // Calculate SHA256 of the marshaled certificate
        auto marshaled = marshal();
        if (marshaled.is_error()) {
            return "";
        }
        
        auto hash_result = sha256(marshaled.value());
        if (hash_result.is_error()) {
            return "";
        }
        
        // Convert to hex string
        std::stringstream ss;
        for (uint8_t byte : hash_result.value()) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return ss.str();
    }
    
    bool is_expired(std::chrono::system_clock::time_point t) const override {
        return t < not_before_ || t > not_after_;
    }
    
    Result<void> verify_private_key(const PrivateKey& key) const override {
        if (key.curve() != cert_curve_to_crypto(curve_)) {
            return Result<void>("Key curve does not match certificate curve");
        }
        
        if (key.public_key().bytes() != public_key_.bytes()) {
            return Result<void>("Private key does not match certificate public key");
        }
        
        return Result<void>();
    }
    
    Result<std::vector<uint8_t>> marshal() const override {
        cert::RawNebulaCertificate raw;
        auto* details = raw.mutable_details();
        
        // Fill in details
        details->set_name(name_);
        details->set_isca(is_ca_);
        details->set_notbefore(std::chrono::system_clock::to_time_t(not_before_));
        details->set_notafter(std::chrono::system_clock::to_time_t(not_after_));
        details->set_publickey(public_key_.bytes().data(), public_key_.bytes().size());
        
        // Set curve
        switch (curve_) {
            case CertCurve::CURVE25519:
                details->set_curve(cert::Curve::CURVE25519);
                break;
            case CertCurve::P256:
                details->set_curve(cert::Curve::P256);
                break;
        }
        
        // Issuer
        if (!issuer_.empty()) {
            // Convert hex string to bytes
            std::vector<uint8_t> issuer_bytes;
            for (size_t i = 0; i < issuer_.length(); i += 2) {
                std::string byte_str = issuer_.substr(i, 2);
                uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
                issuer_bytes.push_back(byte);
            }
            details->set_issuer(issuer_bytes.data(), issuer_bytes.size());
        }
        
        // Networks
        for (const auto& net : networks_) {
            details->add_ips(ntohl(net.ip));
            details->add_ips(net.prefix_length);
        }
        
        // Unsafe networks
        for (const auto& net : unsafe_networks_) {
            details->add_subnets(ntohl(net.ip));
            details->add_subnets(net.prefix_length);
        }
        
        // Groups
        for (const auto& group : groups_) {
            details->add_groups(group);
        }
        
        // Signature
        raw.set_signature(signature_.data(), signature_.size());
        
        // Serialize
        std::string serialized = raw.SerializeAsString();
        return std::vector<uint8_t>(serialized.begin(), serialized.end());
    }
    
    Result<std::vector<uint8_t>> marshal_for_handshakes() const override {
        // For v1 certificates, this is the same as marshal
        return marshal();
    }
    
    Result<std::string> marshal_pem() const override {
        auto marshaled = marshal();
        if (marshaled.is_error()) {
            return Result<std::string>::error(marshaled.error());
        }
        
        // Base64 encode
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* mem = BIO_new(BIO_s_mem());
        BIO_push(b64, mem);
        
        BIO_write(b64, marshaled.value().data(), marshaled.value().size());
        BIO_flush(b64);
        
        BUF_MEM* bptr;
        BIO_get_mem_ptr(b64, &bptr);
        
        std::stringstream ss;
        ss << "-----BEGIN " << NEBULA_CERT_BANNER << "-----\n";
        ss << std::string(bptr->data, bptr->length);
        ss << "-----END " << NEBULA_CERT_BANNER << "-----\n";
        
        BIO_free_all(b64);
        
        return Result<std::string>::success(ss.str());
    }
    
    std::string to_string() const override {
        std::stringstream ss;
        ss << "NebulaCertificate {\n";
        ss << "  Version: " << static_cast<int>(version()) << "\n";
        ss << "  Name: " << name_ << "\n";
        ss << "  Networks: ";
        for (size_t i = 0; i < networks_.size(); ++i) {
            if (i > 0) ss << ", ";
            ss << networks_[i].to_string();
        }
        ss << "\n";
        ss << "  Groups: ";
        for (size_t i = 0; i < groups_.size(); ++i) {
            if (i > 0) ss << ", ";
            ss << groups_[i];
        }
        ss << "\n";
        ss << "  IsCA: " << (is_ca_ ? "true" : "false") << "\n";
        ss << "  NotBefore: " << std::chrono::system_clock::to_time_t(not_before_) << "\n";
        ss << "  NotAfter: " << std::chrono::system_clock::to_time_t(not_after_) << "\n";
        ss << "  Fingerprint: " << fingerprint() << "\n";
        ss << "  Issuer: " << (issuer_.empty() ? "self-signed" : issuer_) << "\n";
        ss << "}";
        return ss.str();
    }
    
private:
    std::string name_;
    std::vector<IpNet> networks_;
    std::vector<IpNet> unsafe_networks_;
    std::vector<std::string> groups_;
    bool is_ca_ = false;
    std::chrono::system_clock::time_point not_before_;
    std::chrono::system_clock::time_point not_after_;
    std::string issuer_;
    PublicKey public_key_;
    CertCurve curve_ = CertCurve::CURVE25519;
    std::vector<uint8_t> signature_;
    std::string raw_details_;  // For signature verification
};

// Certificate base implementation

bool Certificate::contains_ip(VpnIp ip) const {
    for (const auto& net : networks()) {
        if (net.contains(ip)) {
            return true;
        }
    }
    return false;
}

Result<Certificate::Ptr> Certificate::from_pem(const std::string& pem) {
    // Find PEM boundaries
    std::string begin = "-----BEGIN " + std::string(NEBULA_CERT_BANNER) + "-----";
    std::string end = "-----END " + std::string(NEBULA_CERT_BANNER) + "-----";
    
    auto begin_pos = pem.find(begin);
    if (begin_pos == std::string::npos) {
        return Result<Ptr>::error("No certificate found in PEM");
    }
    
    auto end_pos = pem.find(end, begin_pos);
    if (end_pos == std::string::npos) {
        return Result<Ptr>::error("Invalid PEM format");
    }
    
    // Extract base64 content
    auto content_start = begin_pos + begin.length();
    auto content = pem.substr(content_start, end_pos - content_start);
    
    // Decode base64
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(content.data(), content.length());
    BIO_push(b64, mem);
    
    std::vector<uint8_t> decoded;
    decoded.resize(content.length()); // Oversize, will resize later
    
    int len = BIO_read(b64, decoded.data(), decoded.size());
    BIO_free_all(b64);
    
    if (len < 0) {
        return Result<Ptr>::error("Failed to decode base64");
    }
    
    decoded.resize(len);
    
    return unmarshal(decoded);
}

Result<Certificate::Ptr> Certificate::unmarshal(const std::vector<uint8_t>& data) {
    return unmarshal(data.data(), data.size());
}

Result<Certificate::Ptr> Certificate::unmarshal(const uint8_t* data, size_t len) {
    // Try to parse as v1 certificate
    cert::RawNebulaCertificate raw;
    if (!raw.ParseFromArray(data, len)) {
        return Result<Ptr>::error("Failed to parse certificate");
    }
    
    auto cert = std::make_shared<CertificateV1>();
    auto parse_result = cert->parse(raw);
    if (parse_result.is_error()) {
        return Result<Ptr>::error(parse_result.error());
    }
    
    return Result<Ptr>::success(cert);
}

// CertificateAuthority implementation

Result<CertificateAuthority::Ptr> CertificateAuthority::create(Certificate::Ptr ca_cert) {
    if (!ca_cert->is_ca()) {
        return Result<Ptr>("Certificate is not a CA");
    }
    
    auto ca = std::make_shared<CertificateAuthority>();
    ca->ca_certs_[ca_cert->fingerprint()] = ca_cert;
    return ca;
}

Result<void> CertificateAuthority::add_ca(Certificate::Ptr ca_cert) {
    if (!ca_cert->is_ca()) {
        return Result<void>("Certificate is not a CA");
    }
    
    ca_certs_[ca_cert->fingerprint()] = ca_cert;
    return Result<void>();
}

Certificate::Ptr CertificateAuthority::get_ca(const std::string& fingerprint) const {
    auto it = ca_certs_.find(fingerprint);
    if (it != ca_certs_.end()) {
        return it->second;
    }
    return nullptr;
}

Result<Certificate::Ptr> CertificateAuthority::verify_certificate(Certificate::Ptr cert) const {
    // Check if certificate is blocklisted
    if (is_blocklisted(cert->fingerprint())) {
        return Result<Certificate::Ptr>("Certificate is blocklisted");
    }
    
    // Find the issuing CA
    Certificate::Ptr ca_cert = nullptr;
    
    if (cert->issuer().empty()) {
        // Self-signed certificate
        ca_cert = get_ca(cert->fingerprint());
    } else {
        // Certificate signed by a CA
        ca_cert = get_ca(cert->issuer());
    }
    
    if (!ca_cert) {
        return Result<Certificate::Ptr>("Unknown issuer: " + cert->issuer());
    }
    
    // Verify signature
    if (!cert->verify_signature(ca_cert->public_key())) {
        return Result<Certificate::Ptr>("Invalid signature");
    }
    
    // Validate constraints
    auto validate_result = CertificateValidator::validate_constraints(*cert, *ca_cert);
    if (validate_result.is_error()) {
        return Result<Certificate::Ptr>(validate_result.error());
    }
    
    return cert;
}

bool CertificateAuthority::has_expired_ca() const {
    for (const auto& [fp, cert] : ca_certs_) {
        if (cert->is_expired()) {
            return true;
        }
    }
    return false;
}

std::vector<std::string> CertificateAuthority::get_fingerprints() const {
    std::vector<std::string> fingerprints;
    for (const auto& [fp, cert] : ca_certs_) {
        fingerprints.push_back(fp);
    }
    return fingerprints;
}

// CertificateValidator implementation

Result<void> CertificateValidator::validate_constraints(
    const Certificate& cert,
    const Certificate& ca_cert) {
    
    // Check time constraints
    if (cert.not_before() < ca_cert.not_before()) {
        return Result<void>("Certificate valid before CA");
    }
    
    if (cert.not_after() > ca_cert.not_after()) {
        return Result<void>("Certificate valid after CA");
    }
    
    // Check networks
    if (!networks_contain(ca_cert.networks(), cert.networks())) {
        return Result<void>("Certificate networks not allowed by CA");
    }
    
    // Check unsafe networks
    if (!networks_contain(ca_cert.unsafe_networks(), cert.unsafe_networks())) {
        return Result<void>("Certificate unsafe networks not allowed by CA");
    }
    
    // Check groups
    if (!groups_contain(ca_cert.groups(), cert.groups())) {
        return Result<void>("Certificate groups not allowed by CA");
    }
    
    return Result<void>();
}

bool CertificateValidator::networks_contain(
    const std::vector<IpNet>& ca_networks,
    const std::vector<IpNet>& cert_networks) {
    
    // Every cert network must be contained by at least one CA network
    for (const auto& cert_net : cert_networks) {
        bool found = false;
        for (const auto& ca_net : ca_networks) {
            // Check if cert_net is within ca_net
            if (ca_net.contains(cert_net.ip) && 
                cert_net.prefix_length >= ca_net.prefix_length) {
                found = true;
                break;
            }
        }
        if (!found) {
            return false;
        }
    }
    return true;
}

bool CertificateValidator::groups_contain(
    const std::vector<std::string>& ca_groups,
    const std::vector<std::string>& cert_groups) {
    
    // Every cert group must be in CA groups
    for (const auto& cert_group : cert_groups) {
        bool found = false;
        for (const auto& ca_group : ca_groups) {
            if (cert_group == ca_group) {
                found = true;
                break;
            }
        }
        if (!found) {
            return false;
        }
    }
    return true;
}

} // namespace nebula