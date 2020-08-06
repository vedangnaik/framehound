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
            // sleep 1 second between checking for new packets
            struct timespec ts = { 1, 0 };
            nanosleep(&ts, NULL);
        }
        else {
            std::vector<uint8_t> packet = bklg.front();
            bklg.pop();
            emit sendPacketToGUI(packet);
        }
    }
}
