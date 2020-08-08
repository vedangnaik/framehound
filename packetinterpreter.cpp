#include "packetinterpreter.h"

PacketInterpreter::PacketInterpreter(Sniffer* snifferToPrint, QObject *parent) : QObject(parent)
{
    std::cout << "Printer ready to print" << std::endl;
    this->sn = snifferToPrint;
}

void PacketInterpreter::startInterpreting() {
    this->setStopFlag(false);
    while (1) {
        if (this->stopFlag) { break; }

        std::queue<std::vector<uint8_t>>& bklg = this->sn->getPacketBacklog();
        if (bklg.size() == 0) {
            struct timespec ts = { 1, 0 };
            nanosleep(&ts, NULL);
            continue;
        }

        // set up vectors for L2, L3, L4 protocols
        std::vector<uint8_t> packet = bklg.front();
        struct innerProtocolInfo inf = {0, 0};
        std::vector<std::pair<std::string, std::string>> L2, L3, L4;
        std::vector<std::pair<std::string, std::string>> (*protocolToInterpret)(std::vector<uint8_t>& packet, struct innerProtocolInfo& inf);

        // set function pointer to function to interpret this L2 header
        switch(inf.innerProtocolID) {
        default:
            protocolToInterpret = &interpretEthernetHeaders;
        }
        L2 = (*protocolToInterpret)(packet, inf);

        // same as above for L3 header
        switch(inf.innerProtocolID) {
        case 2048: //IPv4
            protocolToInterpret = &interpretIPv4Headers;
            break;
        default:
            protocolToInterpret = &interpretNothing;
        }
        L3 = (*protocolToInterpret)(packet, inf);

        // same as above for L4 header
        switch(inf.innerProtocolID) {
        case 6: //TCP
            protocolToInterpret = &interpretTCPHeaders;
            break;
        default:
            protocolToInterpret = &interpretNothing;
        }
        L4 = (*protocolToInterpret)(packet, inf);

        bklg.pop();
        emit sendProtocolsToGUI(L2, L3, L4,  packet.size() - inf.offsetFromStart);
    }
}
