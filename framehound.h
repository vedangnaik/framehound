#ifndef FRAMEHOUND_H
#define FRAMEHOUND_H

#include "sniffer.h"
#include "packetprinter.h"

#include <QMainWindow>
#include <QThread>
#include <QQueue>
#include <QLabel>

#include <sys/types.h>
#include <ifaddrs.h>


QT_BEGIN_NAMESPACE
namespace Ui { class FrameHound; }
QT_END_NAMESPACE

class FrameHound : public QMainWindow
{
    Q_OBJECT

public:
    FrameHound(QWidget *parent = nullptr);
    ~FrameHound();

private:
    Ui::FrameHound *ui;
    QThread sniffingThread;
    QThread printingThread;
    Sniffer* sni;
    PacketPrinter* prn;

public slots:
//    void receivePacketFromSniffer(uint8_t* packet, ssize_t packetLength);
    void receivePacketFrameFromPrinter(QFrame* packetFrame);

};
#endif // FRAMEHOUND_H
