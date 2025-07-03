#include <iostream>
#include <vector>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <iomanip>

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
    
    std::cout << "Decoded " << len << " bytes:" << std::endl;
    if (len > 0) {
        for (int i = 0; i < len && i < 32; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << static_cast<int>(decoded[i]) << " ";
            if ((i + 1) % 16 == 0) std::cout << std::endl;
        }
        if (len > 32) std::cout << "..." << std::endl;
    }
    
    return 0;
}