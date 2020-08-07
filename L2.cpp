#include "L2.h"


struct innerProtocolInfo interpretEthernetHeaders(
        std::vector<uint8_t> pkt,
        struct innerProtocolInfo inf)
{
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
            pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5]);
    char srcMACaddr[20];
    sprintf(srcMACaddr, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
            pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11]);
    uint16_t innerProtocolID = (pkt[12] * 256) + pkt[13];

    ethHdrExp->setText("Dst MAC Address: " + QString(dstMACaddr) + "\n" +
                    "Src MAC Address: " + QString(srcMACaddr) + "\n" +
                    "Inner Protocol: " + QString::number(innerProtocolID));

    struct innerProtocolInfo ret;
    ret.innerProtocolID = innerProtocolID;
    ret.offsetFromStart = 14;
    ret.innerProtocolFrame = innerProtocolFrame;
    return ret;
}
