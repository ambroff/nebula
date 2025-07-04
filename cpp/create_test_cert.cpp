#include "cert_v1.pb.h"
#include <iostream>
#include <vector>
#include <iomanip>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

std::string base64_encode(const std::vector<uint8_t>& data) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);
    
    BIO_write(b64, data.data(), data.size());
    BIO_flush(b64);
    
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    
    std::string result(bptr->data, bptr->length);
    BIO_free_all(b64);
    
    return result;
}

int main() {
    // Create a proper test certificate
    cert::RawNebulaCertificate cert;
    cert::RawNebulaCertificateDetails* details = cert.mutable_details();
    
    // Set basic details
    details->set_name("test-ca");
    details->set_isca(true);
    
    // Set time (Unix timestamps)
    details->set_notbefore(1600000000);  
    details->set_notafter(1700000000);   
    
    // Set a dummy 32-byte public key for Ed25519
    std::string pubkey(32, 'A');
    details->set_publickey(pubkey);
    
    // Set curve
    details->set_curve(cert::Curve::CURVE25519);
    
    // Add IP (192.168.100.1/24)
    details->add_ips(0xc0a86401);  // 192.168.100.1 in network byte order
    details->add_ips(24);          // prefix length
    
    // Add group
    details->add_groups("test");
    
    // Set a dummy 64-byte signature
    std::string signature(64, 'S');
    cert.set_signature(signature);
    
    // Serialize
    std::string serialized = cert.SerializeAsString();
    std::cout << "Created certificate of " << serialized.size() << " bytes" << std::endl;
    
    // Base64 encode
    std::vector<uint8_t> data(serialized.begin(), serialized.end());
    std::string encoded = base64_encode(data);
    
    std::cout << "-----BEGIN NEBULA CERTIFICATE-----" << std::endl;
    std::cout << encoded;
    std::cout << "-----END NEBULA CERTIFICATE-----" << std::endl;
    
    // Also output C++ test string
    std::cout << std::endl << "C++ test string:" << std::endl;
    std::cout << "const char* test_ca_pem = R\"(-----BEGIN NEBULA CERTIFICATE-----" << std::endl;
    
    // Remove trailing newline from base64
    if (!encoded.empty() && encoded.back() == '\n') {
        encoded.pop_back();
    }
    std::cout << encoded << std::endl;
    std::cout << "-----END NEBULA CERTIFICATE-----)\";" << std::endl;
    
    return 0;
}