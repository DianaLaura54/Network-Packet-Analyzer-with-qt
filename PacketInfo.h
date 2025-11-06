#ifndef PACKETINFO_H
#define PACKETINFO_H

#include <string>
#include <vector>
#include <cstdint>

struct PacketInfo {
    int number;
    std::string timestamp;
    std::string source_ip;
    std::string dest_ip;
    std::string source_mac;
    std::string dest_mac;
    std::string protocol;
    int length;
    int ttl;
    int source_port;
    int dest_port;
    std::string flags;
    std::vector<uint8_t> raw_data;

    PacketInfo() : number(0), length(0), ttl(0), source_port(0), dest_port(0) {}
};

#endif // PACKETINFO_H