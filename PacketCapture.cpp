#include "PacketCapture.h"
#include <cstring>
#include <ctime>
#include <chrono>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
    #pragma comment(lib, "ws2_32.lib")

    struct ethhdr {
        unsigned char h_dest[6];
        unsigned char h_source[6];
        unsigned short h_proto;
    };

    struct iphdr {
        unsigned char ihl:4;
        unsigned char version:4;
        unsigned char tos;
        unsigned short tot_len;
        unsigned short id;
        unsigned short frag_off;
        unsigned char ttl;
        unsigned char protocol;
        unsigned short check;
        unsigned int saddr;
        unsigned int daddr;
    };

    struct tcphdr {
        unsigned short source;
        unsigned short dest;
        unsigned int seq;
        unsigned int ack_seq;
        unsigned short res1:4;
        unsigned short doff:4;
        unsigned short fin:1;
        unsigned short syn:1;
        unsigned short rst:1;
        unsigned short psh:1;
        unsigned short ack:1;
        unsigned short urg:1;
        unsigned short res2:2;
        unsigned short window;
        unsigned short check;
        unsigned short urg_ptr;
    };

    struct udphdr {
        unsigned short source;
        unsigned short dest;
        unsigned short len;
        unsigned short check;
    };

    struct icmphdr {
        unsigned char type;
        unsigned char code;
        unsigned short checksum;
    };

    #define IPPROTO_ICMP 1
    #define IPPROTO_TCP 6
    #define IPPROTO_UDP 17
#else
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <netinet/ip_icmp.h>
    #include <netinet/if_ether.h>
    #include <unistd.h>
#endif

PacketCapture::PacketCapture(QObject *parent)
    : QThread(parent), running(false), packetNumber(0) {
#ifdef _WIN32
    sock = INVALID_SOCKET;
#else
    sock = -1;
#endif
}

PacketCapture::~PacketCapture() {
    stopCapture();
    wait();
    closeSocket();
}

void PacketCapture::stopCapture() {
    running = false;
}

void PacketCapture::setFilter(const std::string& filter) {
    currentFilter = filter;
}

void PacketCapture::run() {
    running = true;
    packetNumber = 0;

    if (!initializeSocket()) {
        emit captureError("Failed to initialize socket. On Linux, run with sudo!");
        return;
    }

    emit captureStarted();

    unsigned char buffer[65536];

    while (running) {
#ifdef _WIN32
        int data_size = recv(sock, (char*)buffer, 65536, 0);
        if (data_size == SOCKET_ERROR) {
            if (running) {
                emit captureError(QString("Socket error: %1").arg(WSAGetLastError()));
            }
            break;
        }

        // Windows raw socket doesn't include Ethernet header
        memmove(buffer + sizeof(struct ethhdr), buffer, data_size);
        memset(buffer, 0, sizeof(struct ethhdr));
        struct ethhdr *eth = (struct ethhdr*)buffer;
        eth->h_proto = htons(0x0800); // IP protocol
        data_size += sizeof(struct ethhdr);
#else
        ssize_t data_size = recvfrom(sock, buffer, 65536, 0, NULL, NULL);
        if (data_size < 0) {
            if (running) {
                emit captureError("Error receiving packet");
            }
            break;
        }
#endif

        if (data_size > 0) {
            PacketInfo packet = parsePacket(buffer, data_size);

            if (matchesFilter(packet)) {
                packetNumber++;
                packet.number = packetNumber;
                emit packetCaptured(packet);
            }
        }

        // Small delay to prevent overwhelming the GUI
        QThread::msleep(1);
    }

    emit captureStopped();
}

bool PacketCapture::initializeSocket() {
#ifdef _WIN32
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return false;
    }

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return false;
    }

    struct hostent *host = gethostbyname(hostname);
    if (host == NULL) {
        closesocket(sock);
        WSACleanup();
        return false;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    memcpy(&addr.sin_addr, host->h_addr_list[0], host->h_length);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return false;
    }

    DWORD optval = 1;
    if (ioctlsocket(sock, SIO_RCVALL, &optval) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return false;
    }
#else
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        return false;
    }
#endif

    return true;
}

void PacketCapture::closeSocket() {
#ifdef _WIN32
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
        WSACleanup();
        sock = INVALID_SOCKET;
    }
#else
    if (sock >= 0) {
        close(sock);
        sock = -1;
    }
#endif
}

PacketInfo PacketCapture::parsePacket(unsigned char* buffer, int size) {
    PacketInfo packet;
    packet.timestamp = getCurrentTime();
    packet.length = size;

    // Store raw data
    packet.raw_data.assign(buffer, buffer + size);

    // Parse Ethernet header
#ifndef _WIN32
    struct ethhdr *eth = (struct ethhdr *)buffer;
    packet.source_mac = macToString(eth->h_source);
    packet.dest_mac = macToString(eth->h_dest);
#endif

    // Parse IP header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    packet.source_ip = ipToString(iph->saddr);
    packet.dest_ip = ipToString(iph->daddr);
    packet.ttl = iph->ttl;

    unsigned int iphdr_len = iph->ihl * 4;

    // Determine protocol
    switch (iph->protocol) {
        case IPPROTO_TCP: {
            packet.protocol = "TCP";
            struct tcphdr *tcph = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + iphdr_len);
            packet.source_port = ntohs(tcph->source);
            packet.dest_port = ntohs(tcph->dest); //network to host

            // TCP flags
            std::string flags;
            if (tcph->fin) flags += "FIN ";
            if (tcph->syn) flags += "SYN ";
            if (tcph->rst) flags += "RST ";
            if (tcph->psh) flags += "PSH ";
            if (tcph->ack) flags += "ACK ";
            if (tcph->urg) flags += "URG ";
            packet.flags = flags;
            break;
        }
        case IPPROTO_UDP: {
            packet.protocol = "UDP";
            struct udphdr *udph = (struct udphdr*)(buffer + sizeof(struct ethhdr) + iphdr_len);
            packet.source_port = ntohs(udph->source);
            packet.dest_port = ntohs(udph->dest);
            break;
        }
        case IPPROTO_ICMP: {
            packet.protocol = "ICMP";
            struct icmphdr *icmph = (struct icmphdr*)(buffer + sizeof(struct ethhdr) + iphdr_len);
            packet.source_port = icmph->type;
            packet.dest_port = icmph->code;
            break;
        }
        default:
            packet.protocol = "Other (" + std::to_string(iph->protocol) + ")";
            break;
    }

    return packet;
}

bool PacketCapture::matchesFilter(const PacketInfo& packet) {
    if (currentFilter.empty()) {
        return true;
    }

    size_t pos = currentFilter.find('=');
    if (pos == std::string::npos) {
        return true;
    }

    std::string key = currentFilter.substr(0, pos);
    std::string value = currentFilter.substr(pos + 1);

    if (key == "protocol") {
        std::string proto_lower = packet.protocol;
        for (auto& c : proto_lower) c = std::tolower(c);
        return proto_lower.find(value) != std::string::npos;
    } else if (key == "src") {
        return packet.source_ip == value;
    } else if (key == "dst") {
        return packet.dest_ip == value;
    } else if (key == "port") {
        int port = std::stoi(value);
        return packet.source_port == port || packet.dest_port == port;
    }

    return true;
}

std::string PacketCapture::getCurrentTime() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    auto timer = std::chrono::system_clock::to_time_t(now);

    std::tm bt = *std::localtime(&timer);
    std::ostringstream oss;
    oss << std::put_time(&bt, "%H:%M:%S");
    oss << '.' << std::setfill('0') << std::setw(3) << ms.count();

    return oss.str();
}

std::string PacketCapture::macToString(unsigned char* mac) {
    std::ostringstream oss;
    for (int i = 0; i < 6; i++) {
        oss << std::hex << std::setfill('0') << std::setw(2) << (int)mac[i];
        if (i < 5) oss << ":";
    }
    return oss.str();
}

std::string PacketCapture::ipToString(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    return std::string(inet_ntoa(addr));
}