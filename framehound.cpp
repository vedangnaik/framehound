// Qt headers
#include "framehound.h"
#include "ui_framehound.h"


FrameHound::FrameHound(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::FrameHound)
{
    ui->setupUi(this);

    // Populate dropdown with all interfaces
    struct ifaddrs* ifa;
    if (getifaddrs(&ifa) == -1) {
        perror("getifaddrs failed: ");
    }
    struct ifaddrs* curr;
    for (curr = ifa; curr != NULL && curr->ifa_addr->sa_family == AF_PACKET; curr = curr->ifa_next) {
        QString ifrName = QString(curr->ifa_name);
        QAction* act = ui->chooseInterfaceMenu->addAction(ifrName);
        connect(act, &QAction::triggered, this, [=]{ startSnifferOnInterface(ifrName); });
    }
    freeifaddrs(ifa);
}

FrameHound::~FrameHound()
{
    delete ui;
}

void FrameHound::receivePacketFromSniffer(uint8_t* packet) {
    std::cout << "Received packet!" << std::endl;
//    this->packetBacklog.enqueue(packet);
}

void FrameHound::startSnifferOnInterface(QString ifrName) {
    this->sn = new Sniffer(ifrName);
    this->sn->moveToThread(&this->sniffingThread);
    connect(this->sn, &Sniffer::sendPacketToGUI, this, &FrameHound::receivePacketFromSniffer);
    connect(ui->startSniffing, &QPushButton::clicked, sn, &Sniffer::startSniffing);
    sniffingThread.start();
}
