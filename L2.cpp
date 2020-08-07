#include "L2.h"


 std::vector<std::pair<std::string, std::string>> interpretEthernetHeaders(std::vector<uint8_t>& pkt, struct innerProtocolInfo& inf) {
    std::vector<std::pair<std::string, std::string>> ethHdr;

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 5; i++) {
        ss << std::setw(2) << static_cast<unsigned>(pkt[i]) << ":";
    }
    ss << std::setw(2) << static_cast<unsigned>(pkt[5]);
    ethHdr.push_back(std::pair<std::string, std::string>(
                         "Dst MAC Address: ", ss.str()));

    ss.str(""); ss.clear();
    for (int i = 6; i < 11; i++) {
        ss << std::setw(2) << static_cast<unsigned>(pkt[i]) << ":";
    }
    ss << std::setw(2) << static_cast<unsigned>(pkt[11]);
    ethHdr.push_back(std::pair<std::string, std::string>(
                         "Src MAC Address: ", ss.str()));

    uint16_t innerProtocolID = (pkt[12] * 256) + pkt[13];
    ethHdr.push_back(std::pair<std::string, std::string>(
                         "Inner Protocol: ", std::to_string(innerProtocolID)));

    inf.innerProtocolID = innerProtocolID;
    inf.offsetFromStart += 14;
    return ethHdr;
}
