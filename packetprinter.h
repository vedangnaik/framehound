#ifndef PACKETPRINTER_H
#define PACKETPRINTER_H

#include <QObject>
#include <QQueue>
#include <QLabel>
#include <QHBoxLayout>
#include <queue>
#include <iostream>

class PacketPrinter : public QObject
{
    Q_OBJECT
public:
    explicit PacketPrinter(QObject *parent = nullptr);

private:
    std::queue<std::vector<uint8_t>> packetBacklog;

signals:
    void sendPacketFrameToGUI(QFrame* packetFrame);

public slots:
    void receivePacketFromSniffer(std::vector<u_int8_t> packet);
    void startPrinting();
};

#endif // PACKETPRINTER_H
