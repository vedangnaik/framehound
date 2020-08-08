#ifndef L4_H
#define L4_H

#include "protocols.h"
#include <bitset>

std::vector<std::pair<std::string, std::string>> intrpTCPHeaders(std::vector<uint8_t>& pkt, struct innerProtocolInfo& inf);

#endif // L4_H