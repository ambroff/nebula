#include "cert_v1.pb.h"
#include <iostream>
#include <vector>

int main() {
    // Create a simple test certificate
    cert::RawNebulaCertificate cert;
    cert::RawNebulaCertificateDetails* details = cert.mutable_details();
    
    details->set_name("test");
    details->set_isca(true);
    details->set_notbefore(1000);
    details->set_notafter(2000);
    details->set_publickey("12345678901234567890123456789012"); // 32 bytes
    details->set_curve(cert::Curve::CURVE25519);
    
    cert.set_signature("signature_data");
    
    // Serialize
    std::string serialized = cert.SerializeAsString();
    std::cout << "Serialized " << serialized.size() << " bytes" << std::endl;
    
    // Try to parse it back
    cert::RawNebulaCertificate parsed;
    if (parsed.ParseFromString(serialized)) {
        std::cout << "Parse successful!" << std::endl;
        std::cout << "Name: " << parsed.details().name() << std::endl;
        std::cout << "IsCA: " << parsed.details().isca() << std::endl;
    } else {
        std::cout << "Parse failed!" << std::endl;
    }
    
    return 0;
}