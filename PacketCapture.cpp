#include "PacketCapture.h"
#include <cstring>
#include <ctime>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cerrno>

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")

// ===================== ETHERNET HEADER (14 bytes) — layer 2 =====================
// Delivers the frame between devices on the same local network.
struct ethhdr {
    unsigned char  h_dest[6];    // Destination MAC address (who receives the frame)
    unsigned char  h_source[6];  // Source MAC address (who sent the frame)
    unsigned short h_proto;      // EtherType = what's inside: 0x0800 IPv4, 0x86DD IPv6, 0x0806 ARP
};

// ===================== IPv4 HEADER (20-60 bytes) — layer 3 ======================
// Routes the packet across networks, from one IP address to another.
struct iphdr {
    unsigned char  ihl:4;        // Header length in 4-byte words (5 = 20 bytes); x4 for bytes
    unsigned char  version:4;    // IP version, always 4 here
    // (ihl listed first because x86 stores the first bit-field in the low bits)
    unsigned char  tos;          // Type of Service: priority / QoS marking
    unsigned short tot_len;      // Total length of the packet in bytes (header + data)
    unsigned short id;           // Identification: groups fragments of the same packet
    unsigned short frag_off;     // Fragment flags (Don't Fragment, More Fragments) + offset
    unsigned char  ttl;          // Time To Live: -1 at each router, dropped at 0 (Windows starts at 128, Linux at 64)
    unsigned char  protocol;     // What's inside: 1 = ICMP, 6 = TCP, 17 = UDP
    unsigned short check;        // Checksum of the IP header (detects corruption)
    unsigned int   saddr;        // Source IP address
    unsigned int   daddr;        // Destination IP address
};

// ===================== TCP HEADER (20-60 bytes) — layer 4 =======================
// Reliable, ordered connection between two programs (web, SSH, email...).
struct tcphdr {
    unsigned short source;       // Source port (sender's program/connection)
    unsigned short dest;         // Destination port (service: 80 HTTP, 443 HTTPS, 22 SSH)
    unsigned int   seq;          // Sequence number: position of this data in the stream
    unsigned int   ack_seq;      // Acknowledgment number: next byte expected from the other side
    unsigned short res1:4;       // Reserved, unused
    unsigned short doff:4;       // Data offset = TCP header length in 4-byte words (5 = 20 bytes)
    unsigned short fin:1;        // FIN: sender is finished, close the connection
    unsigned short syn:1;        // SYN: start a connection (handshake)
    unsigned short rst:1;        // RST: abort the connection immediately
    unsigned short psh:1;        // PSH: pass the data to the application right away
    unsigned short ack:1;        // ACK: the ack_seq field is valid
    unsigned short urg:1;        // URG: urgent data present (rarely used)
    unsigned short res2:2;       // Reserved, unused
    unsigned short window;       // Window size: how many bytes the receiver can accept now (flow control)
    unsigned short check;        // Checksum of TCP header + data
    unsigned short urg_ptr;      // Urgent pointer: end of urgent data, only if urg = 1
};

// ===================== UDP HEADER (8 bytes) — layer 4 ===========================
// Fast, connectionless: no handshake, no ordering, no retransmission (DNS, video, games).
struct udphdr {
    unsigned short source;       // Source port
    unsigned short dest;         // Destination port (53 DNS, 67/68 DHCP, 123 NTP)
    unsigned short len;          // Length of UDP header + data in bytes
    unsigned short check;        // Checksum (optional in IPv4, 0 = not used)
};

// ===================== ICMP HEADER (4 bytes + data) =============================
// Control and error messages for IP (ping, "unreachable", traceroute).
struct icmphdr {
    unsigned char  type;         // Message type: 8 Echo Request (ping), 0 Echo Reply,
    //               3 Destination Unreachable, 11 Time Exceeded
    unsigned char  code;         // Detail for the type (e.g. type 3: 0 net, 1 host, 3 port unreachable)
    unsigned short checksum;     // Checksum of the ICMP message
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
    QMutexLocker locker(&filterMutex);
    currentFilter = filter;
}

void PacketCapture::run() {
    running = true;
    packetNumber = 0;

    if (!initializeSocket()) {
        emit captureError("Failed to initialize socket. On Windows, run as Administrator; on Linux, run with sudo!");
        return;
    }

    emit captureStarted();

    // Extra room for the fake Ethernet header added on Windows
    static const int MAX_PACKET = 65536;
    std::vector<unsigned char> storage(MAX_PACKET + sizeof(struct ethhdr));
    unsigned char *buffer = storage.data();

    while (running) {
#ifdef _WIN32
        int data_size = recv(sock, (char*)buffer, MAX_PACKET, 0);
        if (data_size == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAETIMEDOUT) {
                continue; // no traffic; loop to re-check 'running'
            }
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
        ssize_t data_size = recvfrom(sock, buffer, MAX_PACKET, 0, NULL, NULL);
        if (data_size < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue; // timeout; loop to re-check 'running'
            }
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
        // No sleep here: recv() blocks, and the GUI batches updates itself
    }

    closeSocket();
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

    // Wake up every 500 ms even with no traffic, so Stop works immediately
    DWORD timeoutMs = 500;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));
#else
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        return false;
    }

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
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
    std::string filter;
    {
        QMutexLocker locker(&filterMutex);
        filter = currentFilter;
    }

    if (filter.empty()) {
        return true;
    }

    size_t pos = filter.find('=');
    if (pos == std::string::npos) {
        return true;
    }

    std::string key = filter.substr(0, pos);
    std::string value = filter.substr(pos + 1);

    if (key == "protocol") {
        std::string proto_lower = packet.protocol;
        for (auto& c : proto_lower) c = std::tolower(c);
        return proto_lower.find(value) != std::string::npos;
    } else if (key == "src") {
        return packet.source_ip == value;
    } else if (key == "dst") {
        return packet.dest_ip == value;
    } else if (key == "port") {
        int port;
        try {
            port = std::stoi(value);
        } catch (...) {
            return false; // non-numeric port: match nothing instead of crashing
        }
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