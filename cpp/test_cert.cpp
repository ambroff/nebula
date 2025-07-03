#include "nebula/cert.hpp"
#include <iostream>

using namespace nebula;

int main() {
    // Test certificate PEM 
    const char* test_ca_pem = R"(-----BEGIN NEBULA CERTIFICATE-----
CiAKBG5vZGUSDAgBEP///w8YAiABKgR0ZXN0MIG2hLrlBDi4/4OHBkABSiCvijOD
iEx6+DFsCFPZNe9JQNfD0lJUMqFpBYzui23UhVIg97wyYwE8T3Fft1FNye3d9IQO
np/1p5pLlQGHDLCCBuY=
-----END NEBULA CERTIFICATE-----)";
    
    std::cout << "Parsing certificate..." << std::endl;
    auto cert_result = Certificate::from_pem(test_ca_pem);
    if (cert_result.is_error()) {
        std::cout << "Failed: " << cert_result.error() << std::endl;
        
        // Let's debug by manually extracting the base64
        std::string pem(test_ca_pem);
        std::string begin = "-----BEGIN NEBULA CERTIFICATE-----";
        std::string end = "-----END NEBULA CERTIFICATE-----";
        
        auto begin_pos = pem.find(begin);
        auto end_pos = pem.find(end);
        
        std::cout << "Begin pos: " << begin_pos << std::endl;
        std::cout << "End pos: " << end_pos << std::endl;
        
        if (begin_pos != std::string::npos && end_pos != std::string::npos) {
            auto content_start = begin_pos + begin.length();
            auto content = pem.substr(content_start, end_pos - content_start);
            std::cout << "Base64 content: '" << content << "'" << std::endl;
            std::cout << "Content length: " << content.length() << std::endl;
        }
    } else {
        std::cout << "Success!" << std::endl;
        auto cert = cert_result.value();
        std::cout << cert->to_string() << std::endl;
    }
    
    return 0;
}