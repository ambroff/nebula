#include "nebula/header.hpp"
#include <sstream>
#include <iomanip>

namespace nebula {

std::string Header::to_string() const {
    std::ostringstream oss;
    oss << "ver=" << static_cast<int>(version)
        << " type=" << type_name()
        << " subtype=" << subtype_name()
        << " reserved=0x" << std::hex << reserved
        << " remoteindex=" << std::dec << remote_index
        << " messagecounter=" << message_counter;
    return oss.str();
}

} // namespace nebula