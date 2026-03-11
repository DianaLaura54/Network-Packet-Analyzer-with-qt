#ifndef PACKETPARSER_H
#define PACKETPARSER_H

#include <vector>
#include <string>
#include <cstdint>
#include "PacketInfo.h"

class PacketParser {
public:
    virtual ~PacketParser() = default;
    virtual PacketInfo parse(const unsigned char* buffer, int size);
    
private:
    std::string macToString(const unsigned char* mac);
    std::string ipToString(uint32_t ip);
    std::string getCurrentTime();
};

#endif