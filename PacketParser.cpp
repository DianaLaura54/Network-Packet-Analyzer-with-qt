#include "PacketParser.h"
#include <sstream>
#include <iomanip>
#include <chrono>

#ifdef _WIN32
    #include <winsock2.h>
    struct ethhdr { unsigned char h_dest[6], h_source[6]; unsigned short h_proto; };
    struct iphdr { unsigned char ihl:4, version:4, tos; unsigned short tot_len, id, frag_off; unsigned char ttl, protocol; unsigned short check; unsigned int saddr, daddr; };
    struct tcphdr { unsigned short source, dest; unsigned int seq, ack_seq; unsigned short res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, res2:2, window, check, urg_ptr; };
#else
    #include <arpa/inet.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/if_ether.h>
#endif

PacketInfo PacketParser::parse(const unsigned char* buffer, int size) {
    PacketInfo packet;
    packet.timestamp = getCurrentTime();
    packet.length = size;
    packet.raw_data.assign(buffer, buffer + size);

    struct iphdr *iph = (struct iphdr*)(buffer + 14); // Skip Ethernet
    packet.source_ip = ipToString(iph->saddr);
    packet.dest_ip = ipToString(iph->daddr);
    packet.protocol = (iph->protocol == 6) ? "TCP" : (iph->protocol == 17) ? "UDP" : "Other";

    if (iph->protocol == 6) {
        struct tcphdr *tcph = (struct tcphdr*)(buffer + 14 + (iph->ihl * 4));
        packet.source_port = ntohs(tcph->source);
        packet.dest_port = ntohs(tcph->dest);
    }
    return packet;
}

std::string PacketParser::ipToString(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    return std::string(inet_ntoa(addr));
}

std::string PacketParser::getCurrentTime() {
    auto now = std::chrono::system_clock::now();
    auto timer = std::chrono::system_clock::to_time_t(now);
    std::tm bt = *std::localtime(&timer);
    std::ostringstream oss;
    oss << std::put_time(&bt, "%H:%M:%S");
    return oss.str();
}