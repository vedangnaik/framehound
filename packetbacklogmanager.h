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


class PacketBacklogManager : public QObject
{
    Q_OBJECT
public:
    explicit PacketBacklogManager(Sniffer* snifferToPrint, QObject *parent = nullptr);

private:
    Sniffer* sn;

signals:
    void sendPacketToGUI(std::vector<uint8_t> packet);

public slots:
    void startManaging();
};

#endif // PACKETPRINTER_H
