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


#define FRAMESIZE 2048


class Sniffer : public QObject
{
    Q_OBJECT
public:
    explicit Sniffer(QString ifrName, QObject *parent = nullptr);

private:
    int socketHandle;
    QString ifrName;

signals:
    void sendPacketToGUI(uint8_t* packet);

public slots:
    void startSniffing();
};

#endif // SNIFFER_H
