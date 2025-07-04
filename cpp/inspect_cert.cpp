#include "cert_v1.pb.h"
#include <iostream>
#include <vector>
#include <iomanip>
#include <openssl/bio.h>
#include <openssl/evp.h>

int main() {
    const char* base64 = "CiAKBG5vZGUSDAgBEP///w8YAiABKgR0ZXN0MIG2hLrlBDi4/4OHBkABSiCvijOD"
                        "iEx6+DFsCFPZNe9JQNfD0lJUMqFpBYzui23UhVIg97wyYwE8T3Fft1FNye3d9IQO"
                        "np/1p5pLlQGHDLCCBuY=";
    
    // Decode base64
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(base64, -1);
    BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    
    std::vector<uint8_t> decoded;
    decoded.resize(256);
    
    int len = BIO_read(b64, decoded.data(), decoded.size());
    BIO_free_all(b64);
    
    std::cout << "Decoded " << len << " bytes" << std::endl;
    
    // Try to parse as protobuf
    cert::RawNebulaCertificate cert;
    if (cert.ParseFromArray(decoded.data(), len)) {
        std::cout << "Parse successful!" << std::endl;
        
        if (cert.has_details()) {
            const auto& details = cert.details();
            std::cout << "Details:" << std::endl;
            std::cout << "  Name: " << details.name() << std::endl;
            std::cout << "  IsCA: " << details.isca() << std::endl;
            std::cout << "  IPs count: " << details.ips_size() << std::endl;
            std::cout << "  Groups count: " << details.groups_size() << std::endl;
            std::cout << "  NotBefore: " << details.notbefore() << std::endl;
            std::cout << "  NotAfter: " << details.notafter() << std::endl;
            std::cout << "  PublicKey size: " << details.publickey().size() << std::endl;
            std::cout << "  Curve: " << details.curve() << std::endl;
            std::cout << "  Issuer size: " << details.issuer().size() << std::endl;
        }
        
        std::cout << "Signature size: " << cert.signature().size() << std::endl;
    } else {
        std::cout << "Parse failed!" << std::endl;
        
        // Print hex dump
        std::cout << "Hex dump:" << std::endl;
        for (int i = 0; i < len && i < 64; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << static_cast<int>(decoded[i]) << " ";
            if ((i + 1) % 16 == 0) std::cout << std::endl;
        }
        std::cout << std::endl;
    }
    
    return 0;
}