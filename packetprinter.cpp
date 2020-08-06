#include "packetprinter.h"

PacketPrinter::PacketPrinter(QObject *parent) : QObject(parent)
{
    std::cout << "Printer ready to print" << std::endl;
}

void PacketPrinter::receivePacketFromSniffer(std::vector<uint8_t> packet) {
    this->packetBacklog.push(packet);
}

// HELPERS
struct innerProtocolInfo {
    uint16_t innerProtocolID;
    size_t offsetFromStart;
    QFrame* innerProtocolFrame;
};

struct innerProtocolInfo displayEthernetHeaders(std::vector<uint8_t> ethHdrS, struct innerProtocolInfo inf) {
    QFrame* ethQFrame = inf.innerProtocolFrame;

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
    ret.offsetFromStart = 14;
    ret.innerProtocolFrame = innerProtocolFrame;
    return ret;
}

void PacketPrinter::startPrinting() {
    while (1) {
        std::cout << "printing packet" << std::endl;
        if (this->packetBacklog.size() == 0) {continue;}
        std::vector<uint8_t> packet = this->packetBacklog.front();

        QFrame* packetFrame = new QFrame();
        struct innerProtocolInfo L2 = {0, 0, packetFrame};
        struct innerProtocolInfo L3;

        L3 = displayEthernetHeaders(packet, L2);

        this->packetBacklog.pop();

        emit sendPacketFrameToGUI(packetFrame);
    }
}
