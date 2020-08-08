#include "L4.h"


std::vector<std::pair<std::string, std::string>> interpretTCPHeaders(std::vector<uint8_t>& pkt, struct innerProtocolInfo& inf) {
    std::vector<std::pair<std::string, std::string>> TCPHdr;
    int ofs = inf.offsetFromStart;

    TCPHdr.push_back(std::pair<std::string, std::string>(
                          "Source Port: ", std::to_string(pkt[ofs+0] << 8 | pkt[ofs+1])));
    TCPHdr.push_back(std::pair<std::string, std::string>(
                          "Destination Port: ", std::to_string(pkt[ofs+2] << 8 | pkt[ofs+3])));

    uint32_t seqNum = (uint32_t)(pkt[ofs+4] << 24 | pkt[ofs+5] << 16 | pkt[ofs+6] << 8 | pkt[ofs+7]);
    TCPHdr.push_back(std::pair<std::string, std::string>(
                          "Sequence Number: ", std::to_string(seqNum)));

    uint32_t ackNum = (uint32_t)(pkt[ofs+8] << 24 | pkt[ofs+9] << 16 | pkt[ofs+10] << 8 | pkt[ofs+11]);
    TCPHdr.push_back(std::pair<std::string, std::string>(
                          "Acknowledgement Number: ", std::to_string(ackNum)));

    uint8_t hdrLen = pkt[ofs+12] >> 4;
    TCPHdr.push_back(std::pair<std::string, std::string>(
                          "Header length: ", std::to_string(hdrLen)));
    // Next 6 bits are reserved in the TCP header. They are always zero
    TCPHdr.push_back(std::pair<std::string, std::string>(
                          "Flags: ", std::bitset<6>(pkt[ofs+13]).to_string()));
    TCPHdr.push_back(std::pair<std::string, std::string>(
                          "Window: ", std::to_string(pkt[ofs+14] << 8 | pkt[ofs+15])));

    int checksum = pkt[ofs+16] << 8 | pkt[ofs+17];
    TCPHdr.push_back(std::pair<std::string, std::string>(
                          "Checksum: ", std::to_string(checksum)));
    TCPHdr.push_back(std::pair<std::string, std::string>(
                          "Urgent pointer: ", std::to_string(pkt[ofs+18] << 8 | pkt[ofs+19])));

    TCPHdr.push_back(std::pair<std::string, std::string>(
                          "Options: ", "TODO"));

    inf.innerProtocolID = 0;
    inf.offsetFromStart += (4 * hdrLen);
    return TCPHdr;
}
