// Qt headers
#include "framehound.h"
#include "ui_framehound.h"


FrameHound::FrameHound(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::FrameHound)
{
    ui->setupUi(this);
    sn = new Sniffer();
    sn->moveToThread(&this->sniffingThread);
    connect(sn, &Sniffer::sendPacket, this, &FrameHound::decipherPacket);
    connect(ui->startSniffing, &QPushButton::clicked, sn, &Sniffer::startSniffing);
    sniffingThread.start();
}

FrameHound::~FrameHound()
{
    delete ui;
}

void FrameHound::decipherPacket(uint8_t* packet) {
    std::cout << "Received packet!" << std::endl;
}
