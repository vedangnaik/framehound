#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <errno.h>
#include <unistd.h>

void main() {
    // create a socket listening for IP packets
    int socketHandle = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (socketHandle == -1) { 
        printf("error opening socket\n");
        return;
    }

    // set interface name and create ifreq struct
    const char* ifrName = "lo";
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, ifrName, IFNAMSIZ);

    // set interface to promiscuous mode using ioctl
    // first, get flags
    if (ioctl(socketHandle, SIOCGIFFLAGS, &ifr) == -1) {
        perror("interface flags get failed");
        printf("interface flags: %d\n", ifr.ifr_flags);
        return;
    }
    // now, set promisc bit high
    ifr.ifr_flags |= IFF_PROMISC;
    // now, set flags back
    if (ioctl(socketHandle, SIOCSIFFLAGS, &ifr) == -1) {
        perror("interface flags set failed");
        printf("interface flags: %d\n", ifr.ifr_flags);
        return;
    }

    // get interface index
    if (ioctl(socketHandle, SIOCGIFINDEX, &ifr) == -1) {
        perror("interface index get failed");
        printf("interface index: %d\n", ifr.ifr_ifindex);
    }

    // bind socket to interface using sockaddr_ll
    struct sockaddr_ll sll;
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_IP);
    if (bind(socketHandle, (struct sockaddr*)&sll, sizeof(sll)) == -1) {
        perror("interface bind failed");
        printf("interface index: %d\n", ifr.ifr_ifindex);
        return;
    };
    
    // listen for packets:
    uint8_t buffer[2048];
    while (1) {
        ssize_t numBytesRecv = recvfrom(
            socketHandle, 
            buffer, 
            2048, 
            0, 
            NULL, NULL
        );

        printf("Bytes: %d", numBytesRecv);
        for (int i = 0; i < numBytesRecv; i++) {
            if (i % 8 == 0) { printf("\n"); }
            printf("%.2x ", buffer[i]);
        }
        printf("\n\n");
    }
}