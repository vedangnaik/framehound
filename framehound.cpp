// Qt headers
#include "framehound.h"
#include "ui_framehound.h"


FrameHound::FrameHound(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::FrameHound)
{
    ui->setupUi(this);
    qRegisterMetaType<std::vector<uint8_t>>("std::vector<uint8_t>");

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

    // Start packet printer on separate thread
    this->prn = new PacketPrinter();
    this->prn->moveToThread(&this->printingThread);
    this->printingThread.start();

    connect(this->prn, &PacketPrinter::sendPacketFrameToGUI, this, &FrameHound::receivePacketFrameFromPrinter);
}

FrameHound::~FrameHound()
{
    delete ui;
}


// HELPERS

//struct innerProtocolInfo displayIPHeaders(uint8_t* IPHdrS, ssize_t pktLen, struct innerProtocolInfo inf) {
//    size_t i = inf.offsetFromStart;
//    QFrame* IPQFrame = inf.innerProtocolFrame;

//    IPQFrame->setFrameStyle(QFrame::Box | QFrame::Plain);
//    QHBoxLayout* hl = new QHBoxLayout();
//    QLabel* IPHdrExp = new QLabel();
//    QFrame* innerProtocolFrame = new QFrame();
//    innerProtocolFrame->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
//    hl->addWidget(IPHdrExp);
//    hl->addWidget(innerProtocolFrame);
//    IPQFrame->setLayout(hl);

//    uint8_t hdrLen = IPHdrS[i+0] & 0x0F;
//    uint16_t totalLen = IPHdrS[i+2] + IPHdrS[i+3];
//    uint16_t identifier = (IPHdrS[i+4] * 256) + IPHdrS[i+5];
//    uint8_t flags = (IPHdrS[i+6] & 0b11100000) >> 5;
//    uint16_t fragOffset = ((IPHdrS[i+6] * 256) + IPHdrS[i+7]) & 0x1FFF;
//    uint16_t checksum = (IPHdrS[i+10] * 256) + IPHdrS[i+11];
//    char srcIP[10];
//    sprintf(srcIP, "%d.%d.%d.%d", IPHdrS[i+12], IPHdrS[i+13], IPHdrS[i+14], IPHdrS[i+15]);
//    char dstIP[10];
//    sprintf(dstIP, "%d.%d.%d.%d", IPHdrS[i+16], IPHdrS[i+17], IPHdrS[i+18], IPHdrS[i+19]);

//    IPHdrExp->setText("Version: " + QString::number(IPHdrS[i+0] >> 4) + " | " +
//                      "Header length: " + QString::number(hdrLen) + " | " +
//                      "IP Precedence/DSCP:" + QString(IPHdrS[i+1]) + " | " +
//                      "Total length: " + QString::number(totalLen) + "\n"
//            +
//                      "Identifier: " + QString::number(identifier) + " | " +
//                      "Flags: " + QString::number(flags) + " | " +
//                      "Fragmented Offset: " + QString::number(fragOffset) + "\n"
//            +
//                      "Time to live: " + QString::number(IPHdrS[i+8]) + " | " +
//                      "Inner Protocol: " + QString::number(IPHdrS[i+9]) + " | " +
//                      "Checksum Value: " +  QString::number(checksum) + "\n"
//            +
//                      "Src IP: " + QString(srcIP) + "\n"
//            +
//                      "Dst IP: " + QString(dstIP) + "\n");

//    if (hdrLen == 6) {
//        // TODO: Decipher options and add here
//        IPHdrExp->setText(IPHdrExp->text() + "Options: TODO");
//    } else if (hdrLen== 5) {
//        IPHdrExp->setText(IPHdrExp->text() + "Options: None");
//    }

//    struct innerProtocolInfo ret;
//    ret.innerProtocolID = IPHdrS[i+9];
//    ret.offsetFromStart = inf.offsetFromStart + (4 * hdrLen);
//    ret.innerProtocolFrame = innerProtocolFrame;
//    return ret;
//}

// END HELPERS

//void FrameHound::receivePacketFromSniffer(uint8_t* packet, ssize_t packetLength) {
//    QFrame* packetFrame = new QFrame();
//    struct innerProtocolInfo L2 = {0, 0, packetFrame};
//    struct innerProtocolInfo L3;
//    struct innerProtocolInfo L4;

//    // Switch case needed here to display ARP, PPP, etc. packets
//    L3 = displayEthernetHeaders(packet, packetLength, L2);

//    // Choose function to decipher L3 headers
//    switch(L3.innerProtocolID) {
//    case 2048: //IPv4
//        L4 = displayIPHeaders(packet, packetLength, L3);
//        break;
//    default:
//        break;
//    }

//    // Choose function to decipher L4 headers
//    switch(L4.innerProtocolID) {
//    case 1: // ICMP
//        break;
//    case 6: // TCP
//        break;
//    default:
//        break;
//    }

//    // Append completely deciphered packet to scrollArea
//    ui->packetDisplay->addWidget(packetFrame);
//}

void FrameHound::startSnifferOnInterface(QString ifrName) {
    this->sn = new Sniffer(ifrName);
    this->sn->moveToThread(&this->sniffingThread);
    connect(this->sn, &Sniffer::sendPacketToPrinter, this->prn, &PacketPrinter::receivePacketFromSniffer);
    connect(ui->startSniffing, &QPushButton::clicked, this->sn, &Sniffer::startSniffing);
    connect(ui->startSniffing, &QPushButton::clicked, this->prn, &PacketPrinter::startPrinting);
    sniffingThread.start();
}

void FrameHound::receivePacketFrameFromPrinter(QFrame* packetFrame) {
    std::cout << "adding packet" << std::endl;
    ui->packetDisplay->addWidget(packetFrame);
}
