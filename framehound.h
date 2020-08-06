#ifndef FRAMEHOUND_H
#define FRAMEHOUND_H

#include "sniffer.h"
#include "packetbacklogmanager.h"

#include <QMainWindow>
#include <QThread>
#include <QQueue>
#include <QLabel>

#include <sys/types.h>
#include <ifaddrs.h>
#include <unistd.h>


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
    PacketBacklogManager* prn;

public slots:
    void receivePacketFromManager(std::vector<uint8_t> packet);
//    void stopSniffer();
};
#endif // FRAMEHOUND_H
