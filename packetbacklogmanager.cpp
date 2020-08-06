#include "packetbacklogmanager.h"

PacketBacklogManager::PacketBacklogManager(Sniffer* snifferToPrint, QObject *parent) : QObject(parent)
{
    std::cout << "Printer ready to print" << std::endl;
    this->sn = snifferToPrint;
}

void PacketBacklogManager::startManaging() {
    while (1) {
        if (this->sn->packetBacklog.size() == 0) {
            // sleep 1 second between checking for new packets
            struct timespec ts = { 1, 0 };
            nanosleep(&ts, NULL);
        }
        else {
            std::vector<uint8_t> packet = this->sn->packetBacklog.front();
            this->sn->packetBacklog.pop();
            emit sendPacketToGUI(packet);
            std::cout << "sent packet to manager" << std::endl;
        }
    }
}
