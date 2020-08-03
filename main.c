#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
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

    // no binding, so it'll listen to everything
    
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