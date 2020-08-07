#include "packetbacklogmanager.h"

PacketBacklogManager::PacketBacklogManager(Sniffer* snifferToPrint, QObject *parent) : QObject(parent)
{
    std::cout << "Printer ready to print" << std::endl;
    this->sn = snifferToPrint;
}

void PacketBacklogManager::startManaging() {
    this->setStopFlag(false);
    while (1) {
        if (this->stopFlag) { break; }
        std::queue<std::vector<uint8_t>>& bklg = this->sn->getPacketBacklog();
        if (bklg.size() == 0) {
            struct timespec ts = { 1, 0 };
            nanosleep(&ts, NULL);
            continue;
        }

        std::vector<uint8_t> packet = bklg.front();
        bklg.pop();

        struct innerProtocolInfo inf = {0, 0};
        std::vector<std::pair<std::string, std::string>> L2;
        L2 = interpretEthernetHeaders(packet, inf);

        emit sendProtocolsToGUI(L2);
    }
}
