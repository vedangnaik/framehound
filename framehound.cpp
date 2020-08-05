// Qt headers
#include "framehound.h"
#include "ui_framehound.h"


FrameHound::FrameHound(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::FrameHound)
{
    ui->setupUi(this);
    qRegisterMetaType<ssize_t>("ssize_t");

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


// HELPERS
struct innerProtocolInfo {
    uint8_t* innerProtocolStart;
    QFrame* innerProtocolFrame;
};

struct innerProtocolInfo displayEthernetHeaders(uint8_t* ethHdrS, ssize_t pktLen, QFrame* ethQFrame) {
    ethQFrame->setFrameStyle(QFrame::Box | QFrame::Plain);
    QHBoxLayout* hl = new QHBoxLayout();
    QLabel* ethHdrExp = new QLabel();
    QFrame* innerProtocolFrame = new QFrame();
    innerProtocolFrame->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    hl->addWidget(ethHdrExp);
    hl->addWidget(innerProtocolFrame);
    ethQFrame->setLayout(hl);

    char dstMACaddr[20];
    sprintf(dstMACaddr, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
            ethHdrS[0], ethHdrS[1], ethHdrS[2], ethHdrS[3], ethHdrS[4], ethHdrS[5]);
    char srcMACaddr[20];
    sprintf(srcMACaddr, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
            ethHdrS[6], ethHdrS[7], ethHdrS[8], ethHdrS[9], ethHdrS[10], ethHdrS[11]);
    char innerProtocolID[7];
    sprintf(innerProtocolID, "0x%.2x%.2x", ethHdrS[12], ethHdrS[13]);

    ethHdrExp->setText("Dst MAC Address: " + QString(dstMACaddr) + "\n" +
                    "Src MAC Address: " + QString(srcMACaddr) + "\n" +
                    "Inner Protocol: " + QString(innerProtocolID));

    struct innerProtocolInfo ret;
    ret.innerProtocolStart = ethHdrS + 14;
    ret.innerProtocolFrame = innerProtocolFrame;
    return ret;
}

struct innerProtocolInfo displayIPHeaders(uint8_t* IPHdrs, ssize_t pktLen, QFrame* IPQFrame) {
    IPQFrame->setFrameStyle(QFrame::Box | QFrame::Plain);
    QHBoxLayout* hl = new QHBoxLayout();
    QLabel* IPHdrExp = new QLabel();
    QFrame* innerProtocolFrame = new QFrame();
    innerProtocolFrame->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    hl->addWidget(IPHdrExp);
    hl->addWidget(innerProtocolFrame);
    IPQFrame->setLayout(hl);

    uint8_t hdrLen = IPHdrs[0] & 0x0F;
    uint16_t totalLen = IPHdrs[2] + IPHdrs[3];
    uint16_t identifier = (IPHdrs[4] * 256) + IPHdrs[5];
    uint8_t flags = (IPHdrs[6] & 0b11100000) >> 5;
    uint16_t fragOffset = ((IPHdrs[6] * 256) + IPHdrs[7]) & 0x1FFF;
    uint16_t checksum = (IPHdrs[10] * 256) + IPHdrs[11];
    char srcIP[8];
    sprintf(srcIP, "%d.%d.%d.%d", IPHdrs[12], IPHdrs[13], IPHdrs[14], IPHdrs[15]);
    char dstIP[8];
    sprintf(dstIP, "%d.%d.%d.%d", IPHdrs[16], IPHdrs[17], IPHdrs[18], IPHdrs[19]);

    IPHdrExp->setText("Version: " + QString::number(IPHdrs[0] >> 4) + " | " +
                      "Header length: " + QString::number(hdrLen) + " | " +
                      "IP Precedence/DSCP:" + QString(IPHdrs[1]) + " | " +
                      "Total length: " + QString::number(totalLen) + "\n");
    IPHdrExp->setText(IPHdrExp->text() +
                      "Identifier: " + QString::number(identifier) + " | " +
                      "Flags: " + QString::number(flags) + " | " +
                      "Fragmented Offset: " + QString::number(fragOffset) + "\n");
    IPHdrExp->setText(IPHdrExp->text() +
                      "Time to live: " + QString::number(IPHdrs[8]) + " | " +
                      "Inner Protocol: " + QString::number(IPHdrs[9]) + " | " +
                      "Checksum Value: " +  QString::number(checksum) + "\n");
    IPHdrExp->setText(IPHdrExp->text() +
                      "Src IP: " + QString(srcIP) + "\n" +
                      "Dst IP: " + QString(dstIP) + "\n");

    if (hdrLen == 6) {
        // TODO: Decipher options and add here
        IPHdrExp->setText(IPHdrExp->text() + "Options: TODO");
    } else if (hdrLen== 5) {
        IPHdrExp->setText(IPHdrExp->text() + "Options: None");
    }

    struct innerProtocolInfo ret;
    ret.innerProtocolStart = IPHdrs + (4 * hdrLen);
    ret.innerProtocolFrame = innerProtocolFrame;
    return ret;
}

// END HELPERS

void FrameHound::receivePacketFromSniffer(uint8_t* packet, ssize_t packetLength) {
    QFrame* packetFrame = new QFrame();
    struct innerProtocolInfo l3 = displayEthernetHeaders(packet, packetLength, packetFrame);
    struct innerProtocolInfo l4 = displayIPHeaders(l3.innerProtocolStart, packetLength, l3.innerProtocolFrame);
    ui->packetDisplay->addWidget(packetFrame);
}

void FrameHound::startSnifferOnInterface(QString ifrName) {
    this->sn = new Sniffer(ifrName);
    this->sn->moveToThread(&this->sniffingThread);
    connect(this->sn, &Sniffer::sendPacketToGUI, this, &FrameHound::receivePacketFromSniffer);
    connect(ui->startSniffing, &QPushButton::clicked, sn, &Sniffer::startSniffing);
    sniffingThread.start();
}
