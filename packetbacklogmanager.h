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

#include "protocols.h"


class PacketBacklogManager : public QObject
{
    Q_OBJECT
public:
    explicit PacketBacklogManager(Sniffer* snifferToPrint, QObject *parent = nullptr);
    void setStopFlag(bool c) { this->stopFlag = c; }

private:
    Sniffer* sn;
    bool stopFlag = false;

signals:
    void sendProtocolsToGUI(std::vector<std::pair<std::string, std::string>> L2);

public slots:
    void startManaging();
};

#endif // PACKETPRINTER_H
