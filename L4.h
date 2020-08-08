#ifndef L4_H
#define L4_H

#include "interpreters.h"
#include <bitset>

std::vector<std::pair<std::string, std::string>> interpretTCPHeaders(std::vector<uint8_t>& pkt, struct innerProtocolInfo& inf);

#endif // L4_H
