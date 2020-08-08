#ifndef PROTOCOLS_H
#define PROTOCOLS_H

#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <map>
#include <sstream>
#include <iostream>
#include <iomanip>

#include "L2.h"
#include "L3.h"
#include "L4.h"


struct innerProtocolInfo {
    uint16_t innerProtocolID;
    size_t offsetFromStart;
};

std::vector<std::pair<std::string, std::string>> interpretNothing(std::vector<uint8_t>& pkt, struct innerProtocolInfo& inf);

#endif // PROTOCOLS_H
