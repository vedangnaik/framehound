#ifndef L2_H
#define L2_H

#include <protocols.h>

struct innerProtocolInfo interpretEthernetHeaders(
        std::vector<uint8_t> pkt,
        struct innerProtocolInfo inf);

#endif // L2_H
