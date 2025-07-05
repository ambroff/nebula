#pragma once

#include "types.hpp"
#include <cstring>
#include <stdexcept>

namespace nebula {

// Header constants
constexpr uint8_t HEADER_VERSION = 1;
constexpr size_t HEADER_LEN = 16;
constexpr size_t HEADER_SIZE = HEADER_LEN;  // Alias for compatibility

// Message types
enum class MessageType : uint8_t {
    Handshake   = 0,
    Message     = 1,
    RecvError   = 2,
    LightHouse  = 3,
    Test        = 4,
    CloseTunnel = 5,
    Control     = 6
};

// Message subtypes
enum class MessageSubType : uint8_t {
    None = 0,
    
    // Message subtypes
    MessageRelay = 1,
    
    // Test subtypes
    TestRequest = 0,
    TestReply = 1,
    
    // Handshake subtypes
    HandshakeIXPSK0 = 0,
    HandshakeXXPSK0 = 1
};

// Header structure (16 bytes)
// Layout:
// 0: Version (4 bits) | Type (4 bits)
// 1: Subtype (8 bits)
// 2-3: Reserved (16 bits)
// 4-7: RemoteIndex (32 bits)
// 8-15: MessageCounter (64 bits)
class Header {
public:
    uint8_t version = HEADER_VERSION;
    MessageType type = MessageType::Message;
    MessageSubType subtype = MessageSubType::None;
    uint16_t reserved = 0;
    RemoteIndex remote_index = 0;
    MessageCounter message_counter = 0;
    
    // Default constructor
    Header() = default;
    
    // Constructor with all fields
    Header(MessageType t, MessageSubType st, RemoteIndex ri, MessageCounter mc)
        : type(t), subtype(st), remote_index(ri), message_counter(mc) {}
    
    // Encode header to byte buffer
    // Buffer must have at least HEADER_LEN bytes available
    void encode(uint8_t* buffer) const;
    
    // Decode header from byte buffer
    // Buffer must have at least HEADER_LEN bytes
    // Returns Result<void> with error if decode fails
    Result<void> decode(const uint8_t* buffer, size_t len = HEADER_LEN);
    
    // Get human-readable type name
    std::string type_name() const;
    
    // Get human-readable subtype name
    std::string subtype_name() const;
    
    // String representation for debugging
    std::string to_string() const;
    
    // Static helper to encode directly to buffer
    static void encode(uint8_t* buffer, 
                      MessageType type,
                      MessageSubType subtype,
                      RemoteIndex remote_index,
                      MessageCounter message_counter);
};

// Helper functions
inline const char* message_type_name(MessageType type) {
    switch (type) {
        case MessageType::Handshake:   return "handshake";
        case MessageType::Message:     return "message";
        case MessageType::RecvError:   return "recvError";
        case MessageType::LightHouse:  return "lightHouse";
        case MessageType::Test:        return "test";
        case MessageType::CloseTunnel: return "closeTunnel";
        case MessageType::Control:     return "control";
        default:                       return "unknown";
    }
}

inline const char* message_subtype_name(MessageType type, MessageSubType subtype) {
    switch (type) {
        case MessageType::Message:
            switch (subtype) {
                case MessageSubType::None:         return "none";
                case MessageSubType::MessageRelay: return "relay";
                default:                           return "unknown";
            }
        case MessageType::Test:
            switch (subtype) {
                case MessageSubType::TestRequest: return "testRequest";
                case MessageSubType::TestReply:   return "testReply";
                default:                          return "unknown";
            }
        case MessageType::Handshake:
            switch (subtype) {
                case MessageSubType::HandshakeIXPSK0: return "ix_psk0";
                case MessageSubType::HandshakeXXPSK0: return "xx_psk0";
                default:                              return "unknown";
            }
        default:
            return subtype == MessageSubType::None ? "none" : "unknown";
    }
}

// Implementation of inline methods
inline void Header::encode(uint8_t* buffer) const {
    // Byte 0: Version (upper 4 bits) | Type (lower 4 bits)
    buffer[0] = (version << 4) | (static_cast<uint8_t>(type) & 0x0F);
    
    // Byte 1: Subtype
    buffer[1] = static_cast<uint8_t>(subtype);
    
    // Bytes 2-3: Reserved (big endian)
    buffer[2] = (reserved >> 8) & 0xFF;
    buffer[3] = reserved & 0xFF;
    
    // Bytes 4-7: RemoteIndex (big endian)
    buffer[4] = (remote_index >> 24) & 0xFF;
    buffer[5] = (remote_index >> 16) & 0xFF;
    buffer[6] = (remote_index >> 8) & 0xFF;
    buffer[7] = remote_index & 0xFF;
    
    // Bytes 8-15: MessageCounter (big endian)
    buffer[8]  = (message_counter >> 56) & 0xFF;
    buffer[9]  = (message_counter >> 48) & 0xFF;
    buffer[10] = (message_counter >> 40) & 0xFF;
    buffer[11] = (message_counter >> 32) & 0xFF;
    buffer[12] = (message_counter >> 24) & 0xFF;
    buffer[13] = (message_counter >> 16) & 0xFF;
    buffer[14] = (message_counter >> 8) & 0xFF;
    buffer[15] = message_counter & 0xFF;
}

inline Result<void> Header::decode(const uint8_t* buffer, size_t len) {
    if (len < HEADER_LEN) {
        return Result<void>("Header too short");
    }
    
    // Byte 0: Version and Type
    version = (buffer[0] >> 4) & 0x0F;
    type = static_cast<MessageType>(buffer[0] & 0x0F);
    
    // Byte 1: Subtype
    subtype = static_cast<MessageSubType>(buffer[1]);
    
    // Bytes 2-3: Reserved (big endian)
    reserved = (static_cast<uint16_t>(buffer[2]) << 8) | buffer[3];
    
    // Bytes 4-7: RemoteIndex (big endian)
    remote_index = (static_cast<uint32_t>(buffer[4]) << 24) |
                   (static_cast<uint32_t>(buffer[5]) << 16) |
                   (static_cast<uint32_t>(buffer[6]) << 8) |
                   buffer[7];
    
    // Bytes 8-15: MessageCounter (big endian)
    message_counter = (static_cast<uint64_t>(buffer[8]) << 56) |
                      (static_cast<uint64_t>(buffer[9]) << 48) |
                      (static_cast<uint64_t>(buffer[10]) << 40) |
                      (static_cast<uint64_t>(buffer[11]) << 32) |
                      (static_cast<uint64_t>(buffer[12]) << 24) |
                      (static_cast<uint64_t>(buffer[13]) << 16) |
                      (static_cast<uint64_t>(buffer[14]) << 8) |
                      buffer[15];
    
    return Result<void>();
}

inline std::string Header::type_name() const {
    return message_type_name(type);
}

inline std::string Header::subtype_name() const {
    return message_subtype_name(type, subtype);
}

inline void Header::encode(uint8_t* buffer,
                          MessageType type,
                          MessageSubType subtype,
                          RemoteIndex remote_index,
                          MessageCounter message_counter) {
    Header h(type, subtype, remote_index, message_counter);
    h.encode(buffer);
}

} // namespace nebula