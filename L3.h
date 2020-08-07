#ifndef L3_H
#define L3_H

#include <protocols.h>

std::vector<std::pair<std::string, std::string>> intrpIPv4Headers(std::vector<uint8_t>& pkt, struct innerProtocolInfo& inf);

#endif // L3_H
