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
    uint16_t innerProtocolID;
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
    uint16_t innerProtocolID = (ethHdrS[12] * 256) + ethHdrS[13];

    ethHdrExp->setText("Dst MAC Address: " + QString(dstMACaddr) + "\n" +
                    "Src MAC Address: " + QString(srcMACaddr) + "\n" +
                    "Inner Protocol: " + QString::number(innerProtocolID));

    struct innerProtocolInfo ret;
    ret.innerProtocolID = innerProtocolID;
    ret.innerProtocolStart = ethHdrS + 14;
    ret.innerProtocolFrame = innerProtocolFrame;
    return ret;
}

struct innerProtocolInfo displayIPHeaders(uint8_t* IPHdrS, ssize_t pktLen, QFrame* IPQFrame) {
    IPQFrame->setFrameStyle(QFrame::Box | QFrame::Plain);
    QHBoxLayout* hl = new QHBoxLayout();
    QLabel* IPHdrExp = new QLabel();
    QFrame* innerProtocolFrame = new QFrame();
    innerProtocolFrame->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    hl->addWidget(IPHdrExp);
    hl->addWidget(innerProtocolFrame);
    IPQFrame->setLayout(hl);

    uint8_t hdrLen = IPHdrS[0] & 0x0F;
    uint16_t totalLen = IPHdrS[2] + IPHdrS[3];
    uint16_t identifier = (IPHdrS[4] * 256) + IPHdrS[5];
    uint8_t flags = (IPHdrS[6] & 0b11100000) >> 5;
    uint16_t fragOffset = ((IPHdrS[6] * 256) + IPHdrS[7]) & 0x1FFF;
    uint16_t checksum = (IPHdrS[10] * 256) + IPHdrS[11];
    char srcIP[10];
    sprintf(srcIP, "%d.%d.%d.%d", IPHdrS[12], IPHdrS[13], IPHdrS[14], IPHdrS[15]);
    char dstIP[10];
    sprintf(dstIP, "%d.%d.%d.%d", IPHdrS[16], IPHdrS[17], IPHdrS[18], IPHdrS[19]);

    IPHdrExp->setText("Version: " + QString::number(IPHdrS[0] >> 4) + " | " +
                      "Header length: " + QString::number(hdrLen) + " | " +
                      "IP Precedence/DSCP:" + QString(IPHdrS[1]) + " | " +
                      "Total length: " + QString::number(totalLen) + "\n"
            +
                      "Identifier: " + QString::number(identifier) + " | " +
                      "Flags: " + QString::number(flags) + " | " +
                      "Fragmented Offset: " + QString::number(fragOffset) + "\n"
            +
                      "Time to live: " + QString::number(IPHdrS[8]) + " | " +
                      "Inner Protocol: " + QString::number(IPHdrS[9]) + " | " +
                      "Checksum Value: " +  QString::number(checksum) + "\n"
            +
                      "Src IP: " + QString(srcIP) + "\n"
            +
                      "Dst IP: " + QString(dstIP) + "\n");

    if (hdrLen == 6) {
        // TODO: Decipher options and add here
        IPHdrExp->setText(IPHdrExp->text() + "Options: TODO");
    } else if (hdrLen== 5) {
        IPHdrExp->setText(IPHdrExp->text() + "Options: None");
    }

    struct innerProtocolInfo ret;
    ret.innerProtocolID = IPHdrS[9];
    ret.innerProtocolStart = IPHdrS + (4 * hdrLen);
    ret.innerProtocolFrame = innerProtocolFrame;
    return ret;
}

// END HELPERS

void FrameHound::receivePacketFromSniffer(uint8_t* packet, ssize_t packetLength) {
    QFrame* packetFrame = new QFrame();
    struct innerProtocolInfo L3;
    struct innerProtocolInfo L4;

    // Switch case needed here to display ARP, PPP, etc. packets
    L3 = displayEthernetHeaders(packet, packetLength, packetFrame);

    // Choose function to decipher L3 headers
    switch(L3.innerProtocolID) {
    case 2048: //IPv4
        L4 = displayIPHeaders(L3.innerProtocolStart, packetLength, L3.innerProtocolFrame);
        break;
    default:
        break;
    }

    // Choose function to decipher L4 headers
    switch(L4.innerProtocolID) {
    case 1: // ICMP
        break;
    case 6: // TCP
        break;
    default:
        break;
    }

    // Append completely deciphered packet to scrollArea
    ui->packetDisplay->addWidget(packetFrame);
}

void FrameHound::startSnifferOnInterface(QString ifrName) {
    this->sn = new Sniffer(ifrName);
    this->sn->moveToThread(&this->sniffingThread);
    connect(this->sn, &Sniffer::sendPacketToGUI, this, &FrameHound::receivePacketFromSniffer);
    connect(ui->startSniffing, &QPushButton::clicked, sn, &Sniffer::startSniffing);
    sniffingThread.start();
}
