#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>

void main() {
    // create a socket
    int socketHandle = socket(PF_PACKET, SOCK_RAW, htons(0x0800));
    if (socketHandle == -1) { 
        printf("error opening socket\n");
        return;
    }

    // set the interface to promiscuous mode
    const char* interfaceName = "lo";
    // struct ifreq interfaceInfo;
    // strncpy(interfaceInfo.ifr_name, interfaceName, strlen(interfaceName));
    // ioctl(socketHandle, SIOCGIFFLAGS, &interfaceInfo);
    // interfaceInfo.ifr_flags |= IFF_PROMISC;
    // ioctl(socketHandle, SIOCSIFFLAGS, &interfaceInfo);
    
    // normally, there's no need to bind; it'll automatically be bound to a random free port and to INADDR_ANY. However, we only want to receive packets from a specific interface, so we'll bind the socket to that here.
    // state interface name and set it to promiscuous mode to get all packets 
    int res = setsockopt(
        socketHandle, 
        SOL_SOCKET, 
        SO_BINDTODEVICE, 
        interfaceName, 
        strlen(interfaceName)
    );
    if (res == -1) {
        printf("error opening network interface\n");
        return;
    } else {
        printf("interface bind: %d\n", res);
    }

    // listen for packets:
    printf("Here\n");
    uint8_t buffer[1024];
    while (1) {
        ssize_t numBytesReceived = recvfrom(socketHandle, buffer, 1024, 0, NULL, NULL);
        printf("%d\n", numBytesReceived);
    }
}