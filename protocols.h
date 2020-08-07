#ifndef PROTOCOLS_H
#define PROTOCOLS_H

#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>

#include "L2.h"
#include "L3.h"


struct innerProtocolInfo {
    uint16_t innerProtocolID;
    size_t offsetFromStart;
    QFrame* innerProtocolFrame;
};


#endif // PROTOCOLS_H
