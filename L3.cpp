#include "L3.h"


struct innerProtocolInfo interpretIPHeaders(
        std::vector<uint8_t> pkt,
        struct innerProtocolInfo inf)
{
    size_t i = inf.offsetFromStart;
    QFrame* IPQFrame = inf.innerProtocolFrame;

    IPQFrame->setFrameStyle(QFrame::Box | QFrame::Plain);
    QHBoxLayout* hl = new QHBoxLayout();
    QLabel* IPHdrExp = new QLabel();
    QFrame* innerProtocolFrame = new QFrame();
    innerProtocolFrame->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    hl->addWidget(IPHdrExp);
    hl->addWidget(innerProtocolFrame);
    IPQFrame->setLayout(hl);

    uint8_t hdrLen = pkt[i+0] & 0x0F;
    uint16_t totalLen = pkt[i+2] + pkt[i+3];
    uint16_t identifier = (pkt[i+4] * 256) + pkt[i+5];
    uint8_t flags = (pkt[i+6] & 0b11100000) >> 5;
    uint16_t fragOffset = ((pkt[i+6] * 256) + pkt[i+7]) & 0x1FFF;
    uint16_t checksum = (pkt[i+10] * 256) + pkt[i+11];
    char srcIP[10];
    sprintf(srcIP, "%d.%d.%d.%d", pkt[i+12], pkt[i+13], pkt[i+14], pkt[i+15]);
    char dstIP[10];
    sprintf(dstIP, "%d.%d.%d.%d", pkt[i+16], pkt[i+17], pkt[i+18], pkt[i+19]);

    IPHdrExp->setText("Version: " + QString::number(pkt[i+0] >> 4) + " | " +
                      "Header length: " + QString::number(hdrLen) + " | " +
                      "IP Precedence/DSCP:" + QString(pkt[i+1]) + " | " +
                      "Total length: " + QString::number(totalLen) + "\n"
            +
                      "Identifier: " + QString::number(identifier) + " | " +
                      "Flags: " + QString::number(flags) + " | " +
                      "Fragmented Offset: " + QString::number(fragOffset) + "\n"
            +
                      "Time to live: " + QString::number(pkt[i+8]) + " | " +
                      "Inner Protocol: " + QString::number(pkt[i+9]) + " | " +
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
    ret.innerProtocolID = pkt[i+9];
    ret.offsetFromStart = inf.offsetFromStart + (4 * hdrLen);
    ret.innerProtocolFrame = innerProtocolFrame;
    return ret;
}
