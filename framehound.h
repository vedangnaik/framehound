#ifndef FRAMEHOUND_H
#define FRAMEHOUND_H

#include <QMainWindow>
#include <QThread>
#include "sniffer.h"

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
    Sniffer* sn;

public slots:
    void decipherPacket(uint8_t* packet);

};
#endif // FRAMEHOUND_H
