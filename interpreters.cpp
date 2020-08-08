#include "interpreters.h"

std::vector<std::pair<std::string, std::string>> interpretNothing(std::vector<uint8_t>& pkt, struct innerProtocolInfo& inf) {
    std::vector<std::pair<std::string, std::string>> nothing;
    nothing.push_back(std::pair<std::string, std::string>(
                          "Protocol: ", "Not implemented"));
    return nothing;
}
