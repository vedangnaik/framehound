#ifndef FRAMEHOUND_H
#define FRAMEHOUND_H

#include "sniffer.h"
#include "packetbacklogmanager.h"
#include "protocols.h"

#include <QMainWindow>
#include <QCloseEvent>
#include <QMessageBox>
#include <QThread>
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
    QThread managingThread;
    Sniffer* sni;
    PacketBacklogManager* mng;

public slots:
    void receivePacketFromManager(std::vector<uint8_t> packet);
    void closeEvent(QCloseEvent* event);
};

QFrame* packetFrameMaker(QFrame* outerFrame, QString explanation);

#endif // FRAMEHOUND_H
