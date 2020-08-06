#ifndef SNIFFER_H
#define SNIFFER_H

#include <QObject>
// C headers
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
// C++ headers
#include <iostream>
#include <string>
#include <cstdio>
#include <queue>
#include <unistd.h>


#define FRAMESIZE 2048


class Sniffer : public QObject
{
    Q_OBJECT
public:
    explicit Sniffer(QObject *parent = nullptr);
    void setIfrName(QString ifrName) { this->ifrName = ifrName; }
    std::queue<std::vector<uint8_t>>& getPacketBacklog() { return this->packetBacklog; }
    void setStopFlag(bool c) { this->stopFlag = c; }

private:
    int socketHandle;
    QString ifrName;
    std::queue<std::vector<uint8_t>> packetBacklog;
    bool stopFlag = false;

signals:

public slots:
    void sniff();
};

#endif // SNIFFER_H
