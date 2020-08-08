#ifndef L3_H
#define L3_H

#include "interpreters.h"

std::vector<std::pair<std::string, std::string>> interpretIPv4Headers(std::vector<uint8_t>& pkt, struct innerProtocolInfo& inf);

#endif // L3_H
