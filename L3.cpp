#include "L3.h"


std::vector<std::pair<std::string, std::string>> intrpIPv4Headers(std::vector<uint8_t>& pkt, struct innerProtocolInfo& inf) {
    std::vector<std::pair<std::string, std::string>> IPv4Hdr;
    int i = inf.offsetFromStart;

    int hdrLen = pkt[i+0] & 0x0F;
    IPv4Hdr.push_back(std::pair<std::string, std::string>(
                          "Version: ", std::to_string(pkt[i+0] >> 4)));
    IPv4Hdr.push_back(std::pair<std::string, std::string>(
                          "Header Length: ", std::to_string(hdrLen)));
    IPv4Hdr.push_back(std::pair<std::string, std::string>(
                          "IP Precedence/DSCP: ", std::to_string(pkt[i+1])));
    IPv4Hdr.push_back(std::pair<std::string, std::string>(
                          "Total Length: ", std::to_string(pkt[i+2] + pkt[i+3])));

    IPv4Hdr.push_back(std::pair<std::string, std::string>(
                          "Identifier: ", std::to_string((pkt[i+4] * 256) + pkt[i+5])));
    IPv4Hdr.push_back(std::pair<std::string, std::string>(
                          "Flags: ", std::to_string((pkt[i+6] & 0b11100000) >> 5)));
    IPv4Hdr.push_back(std::pair<std::string, std::string>(
                          "Fragment Offset: ", std::to_string(((pkt[i+6] * 256) + pkt[i+7]) & 0x1FFF)));

    uint8_t innerProtocolID = pkt[i+9];
    uint16_t checksum = (pkt[i+10] * 256) + pkt[i+11];
    IPv4Hdr.push_back(std::pair<std::string, std::string>(
                          "Time to Live: ", std::to_string(pkt[i+8])));
    IPv4Hdr.push_back(std::pair<std::string, std::string>(
                          "Protocol: ", std::to_string(innerProtocolID)));
    IPv4Hdr.push_back(std::pair<std::string, std::string>(
                          "Header Checksum: ", std::to_string(checksum)));

    std::stringstream srcss;
    srcss << (int)pkt[i+12] << "." << (int)pkt[i+13] << "." << (int)pkt[i+14] << "." << (int)pkt[i+15];
    IPv4Hdr.push_back(std::pair<std::string, std::string>(
                          "Source IP Address: ", srcss.str()));

    std::stringstream dstss;
    dstss << (int)pkt[i+16] << "." << (int)pkt[i+17] << "." << (int)pkt[i+18] << "." << (int)pkt[i+19];
    IPv4Hdr.push_back(std::pair<std::string, std::string>(
                          "Destination IP Address: ", dstss.str()));

    if (hdrLen == 6) {
        // TODO: Decipher options and add here
        IPv4Hdr.push_back(std::pair<std::string, std::string>(
                              "Options: ", "TODO"));
    } else if (hdrLen== 5) {
        IPv4Hdr.push_back(std::pair<std::string, std::string>(
                              "Options: ", "None"));
    }

    inf.innerProtocolID = innerProtocolID;
    inf.offsetFromStart += (4 * hdrLen);
    return IPv4Hdr;
}
