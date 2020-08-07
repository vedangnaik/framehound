#ifndef L3_H
#define L3_H

#include <protocols.h>

struct innerProtocolInfo interpretIPHeaders(
        std::vector<uint8_t> pkt,
        struct innerProtocolInfo inf);

#endif // L3_H
