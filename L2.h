#ifndef L2_H
#define L2_H

#include "protocols.h"

std::vector<std::pair<std::string, std::string>> interpretEthernetHeaders(std::vector<uint8_t>& pkt, struct innerProtocolInfo& inf);

#endif // L2_H
