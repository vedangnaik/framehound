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


class PacketPrinter : public QObject
{
    Q_OBJECT
public:
    explicit PacketPrinter(Sniffer* snifferToPrint, QObject *parent = nullptr);

private:
    Sniffer* sn;

signals:
    void sendPacketFrameToGUI(QFrame* packetFrame);

public slots:
    void startPrinting();
};

#endif // PACKETPRINTER_H
