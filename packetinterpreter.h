#ifndef PACKETPRINTER_H
#define PACKETPRINTER_H

#include "sniffer.h"

#include <QObject>
#include <QQueue>
#include <QLabel>
#include <QHBoxLayout>

#include <queue>
#include <iostream>
#include <time.h>

#include "interpreters.h"


class PacketInterpreter : public QObject
{
    Q_OBJECT
public:
    explicit PacketInterpreter(Sniffer* snifferToPrint, QObject *parent = nullptr);
    void setStopFlag(bool c) { this->stopFlag = c; }

private:
    Sniffer* sn;
    bool stopFlag = false;

signals:
    void sendProtocolsToGUI(
            std::vector<std::pair<std::string, std::string>> L2,
            std::vector<std::pair<std::string, std::string>> L3,
            std::vector<std::pair<std::string, std::string>> L4,
            size_t dataLen);

public slots:
    void startInterpreting();
};

#endif // PACKETPRINTER_H
