#ifndef FRAMEHOUND_H
#define FRAMEHOUND_H

#include "sniffer.h"
#include "packetinterpreter.h"
#include "interpreters.h"

#include <QMainWindow>
#include <QCloseEvent>
#include <QMessageBox>
#include <QThread>
#include <QLabel>
#include <QRadioButton>

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
    PacketInterpreter* mng;

public slots:
    void receiveProtocolsFromManager(
            std::vector<std::pair<std::string, std::string>> L2,
            std::vector<std::pair<std::string, std::string>> L3,
            std::vector<std::pair<std::string, std::string>> L4,
            size_t dataLen);
    void closeEvent(QCloseEvent* event);
};

QFrame* makeProtocolFrame(QString explanation, QFrame* innerFrame,
                          int lineWidth, int midLineWidth,
                          int shape, int shadow);

#endif // FRAMEHOUND_H
