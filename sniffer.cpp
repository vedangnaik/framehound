#include "sniffer.h"

Sniffer::Sniffer(QString ifrName, QObject *parent) : QObject(parent)
{
    this->ifrName = ifrName;
    std::cout << "Sniffer is ready to sniff: " << ifrName.toStdString() << std::endl;
}

void Sniffer::startSniffing() {
    std::cout << "Sniffer has started sniffing" << std::endl;
    this->socketHandle = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (this->socketHandle == -1) {
        perror("error opening socket\n");
    }

    // set interface name and create ifreq struct
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, this->ifrName.toStdString().c_str(), IFNAMSIZ);

    // set interface to promiscuous mode using ioctl
    // first, get flags
    if (ioctl(this->socketHandle, SIOCGIFFLAGS, &ifr) == -1) {
        perror("interface flags get failed");
        std::cout << "interface flags: " << ifr.ifr_flags << std::endl;
    }
    // now, set promisc bit high
    ifr.ifr_flags |= IFF_PROMISC;
    // now, set flags back
    if (ioctl(this->socketHandle, SIOCSIFFLAGS, &ifr) == -1) {
        perror("interface flags set failed");
        std::cout << "interface flags: " << ifr.ifr_flags << std::endl;
    }

    // get interface index
    if (ioctl(this->socketHandle, SIOCGIFINDEX, &ifr) == -1) {
        perror("interface index get failed");
        std::cout << "interface index: " << ifr.ifr_ifindex << std::endl;
    }

    // bind socket to interface using sockaddr_ll
    struct sockaddr_ll sll;
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_IP);
    if (bind(this->socketHandle, (struct sockaddr*)&sll, sizeof(sll)) == -1) {
        perror("interface bind failed");
        std::cout << "interface index: " << ifr.ifr_ifindex << std::endl;
    };

    // read incoming packets
    uint8_t buffer[FRAMESIZE];
    while (1) {
        ssize_t numBytesRecv = recvfrom(this->socketHandle, buffer, FRAMESIZE, 0, NULL, NULL);
        if (numBytesRecv > 0) {
            std::vector<uint8_t> cp(buffer, buffer+numBytesRecv);
            emit sendPacketToPrinter(cp);
        }
    }
}
