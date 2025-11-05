#include <iostream>
#include <iomanip>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #pragma comment(lib, "ws2_32.lib")

    // Define Linux-style structures for Windows
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
        union {
            struct {
                unsigned short id;
                unsigned short sequence;
            } echo;
            unsigned int gateway;
        } un;
    };

    #define IPPROTO_ICMP 1
    #define IPPROTO_TCP 6
    #define IPPROTO_UDP 17
    #define ETH_P_ALL 0x0003
#else
    #include <arpa/inet.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <netinet/ip_icmp.h>
    #include <netinet/if_ether.h>
    #include <unistd.h>
#endif

enum class FilterType {
    NONE,
    PROTOCOL,
    SOURCE_IP,
    DEST_IP,
    SOURCE_PORT,
    DEST_PORT,
    PORT
};

struct PacketFilter {
    FilterType type;
    std::string value;
    int protocol;
    uint32_t ip_addr;
    uint16_t port;

    PacketFilter() : type(FilterType::NONE), protocol(-1), ip_addr(0), port(0) {}
};

class PacketAnalyzer {
private:
#ifdef _WIN32
    SOCKET sock;
    WSADATA wsa;
#else
    int sock;
#endif
    unsigned char buffer[65536];
    int tcp_count = 0;
    int udp_count = 0;
    int icmp_count = 0;
    int other_count = 0;
    int filtered_count = 0;
    std::vector<PacketFilter> filters;

    void printEthernetHeader(unsigned char* buf) {
        struct ethhdr *eth = (struct ethhdr *)buf;

        std::cout << "\n=== Ethernet Header ===" << std::endl;
        std::cout << "Source MAC: ";
        for(int i = 0; i < 6; i++) {
            printf("%.2X", eth->h_source[i]);
            if(i < 5) std::cout << ":";
        }
        std::cout << "\nDest MAC: ";
        for(int i = 0; i < 6; i++) {
            printf("%.2X", eth->h_dest[i]);
            if(i < 5) std::cout << ":";
        }
#ifdef _WIN32
        std::cout << "\nProtocol: " << ntohs(eth->h_proto) << std::endl;
#else
        std::cout << "\nProtocol: " << ntohs(eth->h_proto) << std::endl;
#endif
    }

    std::string ipToString(uint32_t ip) {
        struct in_addr addr;
        addr.s_addr = ip;
        return std::string(inet_ntoa(addr));
    }

    void printIPHeader(unsigned char* buf) {
        struct iphdr *iph = (struct iphdr*)(buf + sizeof(struct ethhdr));

        std::cout << "\n=== IP Header ===" << std::endl;
        std::cout << "Version: " << (unsigned int)iph->version << std::endl;
        std::cout << "Header Length: " << (unsigned int)iph->ihl * 4 << " bytes" << std::endl;
        std::cout << "Type of Service: " << (unsigned int)iph->tos << std::endl;
        std::cout << "Total Length: " << ntohs(iph->tot_len) << " bytes" << std::endl;
        std::cout << "TTL: " << (unsigned int)iph->ttl << std::endl;
        std::cout << "Protocol: " << (unsigned int)iph->protocol << std::endl;
        std::cout << "Source IP: " << ipToString(iph->saddr) << std::endl;
        std::cout << "Dest IP: " << ipToString(iph->daddr) << std::endl;
    }

    void printTCPHeader(unsigned char* buf, int size) {
        struct iphdr *iph = (struct iphdr*)(buf + sizeof(struct ethhdr));
        unsigned int iphdr_len = iph->ihl * 4;
        struct tcphdr *tcph = (struct tcphdr*)(buf + sizeof(struct ethhdr) + iphdr_len);

        std::cout << "\n=== TCP Header ===" << std::endl;
        std::cout << "Source Port: " << ntohs(tcph->source) << std::endl;
        std::cout << "Dest Port: " << ntohs(tcph->dest) << std::endl;
        std::cout << "Sequence Number: " << ntohl(tcph->seq) << std::endl;
        std::cout << "Ack Number: " << ntohl(tcph->ack_seq) << std::endl;
        std::cout << "Header Length: " << (unsigned int)tcph->doff * 4 << " bytes" << std::endl;
        std::cout << "Flags: ";
        if(tcph->urg) std::cout << "URG ";
        if(tcph->ack) std::cout << "ACK ";
        if(tcph->psh) std::cout << "PSH ";
        if(tcph->rst) std::cout << "RST ";
        if(tcph->syn) std::cout << "SYN ";
        if(tcph->fin) std::cout << "FIN ";
        std::cout << std::endl;
        std::cout << "Window Size: " << ntohs(tcph->window) << std::endl;

        tcp_count++;
    }

    void printUDPHeader(unsigned char* buf) {
        struct iphdr *iph = (struct iphdr*)(buf + sizeof(struct ethhdr));
        unsigned int iphdr_len = iph->ihl * 4;
        struct udphdr *udph = (struct udphdr*)(buf + sizeof(struct ethhdr) + iphdr_len);

        std::cout << "\n=== UDP Header ===" << std::endl;
        std::cout << "Source Port: " << ntohs(udph->source) << std::endl;
        std::cout << "Dest Port: " << ntohs(udph->dest) << std::endl;
        std::cout << "Length: " << ntohs(udph->len) << " bytes" << std::endl;

        udp_count++;
    }

    void printICMPHeader(unsigned char* buf) {
        struct iphdr *iph = (struct iphdr*)(buf + sizeof(struct ethhdr));
        unsigned int iphdr_len = iph->ihl * 4;
        struct icmphdr *icmph = (struct icmphdr*)(buf + sizeof(struct ethhdr) + iphdr_len);

        std::cout << "\n=== ICMP Header ===" << std::endl;
        std::cout << "Type: " << (unsigned int)icmph->type << std::endl;
        std::cout << "Code: " << (unsigned int)icmph->code << std::endl;

        icmp_count++;
    }

    bool matchesFilter(unsigned char* buf) {
        if(filters.empty()) return true;

        struct iphdr *iph = (struct iphdr*)(buf + sizeof(struct ethhdr));
        unsigned int iphdr_len = iph->ihl * 4;

        for(const auto& filter : filters) {
            switch(filter.type) {
                case FilterType::PROTOCOL:
                    if(iph->protocol == filter.protocol)
                        return true;
                    break;

                case FilterType::SOURCE_IP:
                    if(iph->saddr == filter.ip_addr)
                        return true;
                    break;

                case FilterType::DEST_IP:
                    if(iph->daddr == filter.ip_addr)
                        return true;
                    break;

                case FilterType::SOURCE_PORT:
                    if(iph->protocol == IPPROTO_TCP) {
                        struct tcphdr *tcph = (struct tcphdr*)(buf + sizeof(struct ethhdr) + iphdr_len);
                        if(ntohs(tcph->source) == filter.port)
                            return true;
                    } else if(iph->protocol == IPPROTO_UDP) {
                        struct udphdr *udph = (struct udphdr*)(buf + sizeof(struct ethhdr) + iphdr_len);
                        if(ntohs(udph->source) == filter.port)
                            return true;
                    }
                    break;

                case FilterType::DEST_PORT:
                    if(iph->protocol == IPPROTO_TCP) {
                        struct tcphdr *tcph = (struct tcphdr*)(buf + sizeof(struct ethhdr) + iphdr_len);
                        if(ntohs(tcph->dest) == filter.port)
                            return true;
                    } else if(iph->protocol == IPPROTO_UDP) {
                        struct udphdr *udph = (struct udphdr*)(buf + sizeof(struct ethhdr) + iphdr_len);
                        if(ntohs(udph->dest) == filter.port)
                            return true;
                    }
                    break;

                case FilterType::PORT:
                    if(iph->protocol == IPPROTO_TCP) {
                        struct tcphdr *tcph = (struct tcphdr*)(buf + sizeof(struct ethhdr) + iphdr_len);
                        if(ntohs(tcph->source) == filter.port || ntohs(tcph->dest) == filter.port)
                            return true;
                    } else if(iph->protocol == IPPROTO_UDP) {
                        struct udphdr *udph = (struct udphdr*)(buf + sizeof(struct ethhdr) + iphdr_len);
                        if(ntohs(udph->source) == filter.port || ntohs(udph->dest) == filter.port)
                            return true;
                    }
                    break;

                default:
                    break;
            }
        }
        return false;
    }

public:
#ifdef _WIN32
    PacketAnalyzer() : sock(INVALID_SOCKET) {}
#else
    PacketAnalyzer() : sock(-1) {}
#endif

    bool initialize() {
#ifdef _WIN32
     // Initialize Winsock
        if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            std::cerr << "Error: Failed to initialize Winsock. Error Code: " << WSAGetLastError() << std::endl;
            return false;
        }

        // Create raw socket
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
        if(sock == INVALID_SOCKET) {
            std::cerr << "Error: Failed to create socket. Error Code: " << WSAGetLastError() << std::endl;
            std::cerr << "Note: Run as Administrator on Windows!" << std::endl;
            WSACleanup();
            return false;
        }

        // Get local IP address
        char hostname[256];
        if(gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
            std::cerr << "Error: Failed to get hostname" << std::endl;
            closesocket(sock);
            WSACleanup();
            return false;
        }

        struct hostent* host = gethostbyname(hostname);
        if(host == NULL) {
            std::cerr << "Error: Failed to get host info" << std::endl;
            closesocket(sock);
            WSACleanup();
            return false;
        }

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = 0;
        memcpy(&addr.sin_addr.S_un.S_addr, host->h_addr_list[0], host->h_length);

        // Bind socket
        if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            std::cerr << "Error: Failed to bind socket. Error Code: " << WSAGetLastError() << std::endl;
            closesocket(sock);
            WSACleanup();
            return false;
        }

        // Set socket to promiscuous mode
        DWORD dwValue = 1;
        if(ioctlsocket(sock, SIO_RCVALL, &dwValue) == SOCKET_ERROR) {
            std::cerr << "Error: Failed to set promiscuous mode. Error Code: " << WSAGetLastError() << std::endl;
            closesocket(sock);
            WSACleanup();
            return false;
        }

        std::cout << "Socket created successfully. Capturing on: " << inet_ntoa(addr.sin_addr) << std::endl;
#else
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if(sock < 0) {
            std::cerr << "Error: Failed to create socket. Run with sudo!" << std::endl;
            return false;
        }
        std::cout << "Socket created successfully. Starting packet capture..." << std::endl;
#endif
        return true;
    }

    void addFilter(const std::string& filter_str) {
        PacketFilter filter;

        size_t pos = filter_str.find('=');
        if(pos == std::string::npos) {
            std::cerr << "Invalid filter format. Use key=value" << std::endl;
            return;
        }

        std::string key = filter_str.substr(0, pos);
        std::string value = filter_str.substr(pos + 1);

        if(key == "protocol" || key == "proto") {
            filter.type = FilterType::PROTOCOL;
            if(value == "tcp" || value == "TCP") {
                filter.protocol = IPPROTO_TCP;
                std::cout << "Filter added: TCP packets only" << std::endl;
            } else if(value == "udp" || value == "UDP") {
                filter.protocol = IPPROTO_UDP;
                std::cout << "Filter added: UDP packets only" << std::endl;
            } else if(value == "icmp" || value == "ICMP") {
                filter.protocol = IPPROTO_ICMP;
                std::cout << "Filter added: ICMP packets only" << std::endl;
            } else {
                filter.protocol = std::stoi(value);
                std::cout << "Filter added: Protocol " << filter.protocol << " only" << std::endl;
            }
        } else if(key == "src" || key == "source") {
            filter.type = FilterType::SOURCE_IP;
            filter.ip_addr = inet_addr(value.c_str());
            std::cout << "Filter added: Source IP = " << value << std::endl;
        } else if(key == "dst" || key == "dest") {
            filter.type = FilterType::DEST_IP;
            filter.ip_addr = inet_addr(value.c_str());
            std::cout << "Filter added: Destination IP = " << value << std::endl;
        } else if(key == "sport" || key == "srcport") {
            filter.type = FilterType::SOURCE_PORT;
            filter.port = std::stoi(value);
            std::cout << "Filter added: Source Port = " << filter.port << std::endl;
        } else if(key == "dport" || key == "dstport") {
            filter.type = FilterType::DEST_PORT;
            filter.port = std::stoi(value);
            std::cout << "Filter added: Destination Port = " << filter.port << std::endl;
        } else if(key == "port") {
            filter.type = FilterType::PORT;
            filter.port = std::stoi(value);
            std::cout << "Filter added: Port = " << filter.port << " (source or destination)" << std::endl;
        } else {
            std::cerr << "Unknown filter type: " << key << std::endl;
            return;
        }

        filters.push_back(filter);
    }

    void capturePackets(int max_packets = 10) {
        int displayed = 0;
        int total = 0;

        while(displayed < max_packets) {
#ifdef _WIN32
            int data_size = recv(sock, (char*)buffer, 65536, 0);
            if(data_size == SOCKET_ERROR) {
                std::cerr << "Error receiving packet. Error Code: " << WSAGetLastError() << std::endl;
                continue;
            }

            // On Windows raw sockets, we don't get Ethernet header, so we need to fake it
            // Move IP data forward to make room for fake Ethernet header
            memmove(buffer + sizeof(struct ethhdr), buffer, data_size);
            memset(buffer, 0, sizeof(struct ethhdr));
            struct ethhdr *eth = (struct ethhdr*)buffer;
            eth->h_proto = htons(0x0800); // IP protocol
            data_size += sizeof(struct ethhdr);
#else
            ssize_t data_size = recvfrom(sock, buffer, 65536, 0, NULL, NULL);
            if(data_size < 0) {
                std::cerr << "Error receiving packet" << std::endl;
                continue;
            }
#endif

            total++;

            if(!matchesFilter(buffer)) {
                filtered_count++;
                continue;
            }

            displayed++;

            std::cout << "\n\n" << std::string(60, '=') << std::endl;
            std::cout << "Packet #" << displayed << " (Total captured: " << total << ", Size: " << data_size << " bytes)" << std::endl;
            std::cout << std::string(60, '=') << std::endl;

#ifndef _WIN32
            printEthernetHeader(buffer);
#endif

            struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));

            printIPHeader(buffer);

            switch(iph->protocol) {
                case IPPROTO_TCP:
                    printTCPHeader(buffer, data_size);
                    break;
                case IPPROTO_UDP:
                    printUDPHeader(buffer);
                    break;
                case IPPROTO_ICMP:
                    printICMPHeader(buffer);
                    break;
                default:
                    other_count++;
                    std::cout << "\nOther protocol: " << (unsigned int)iph->protocol << std::endl;
                    break;
            }
        }

        printStatistics();
    }

    void printStatistics() {
        std::cout << "\n\n" << std::string(60, '=') << std::endl;
        std::cout << "CAPTURE STATISTICS" << std::endl;
        std::cout << std::string(60, '=') << std::endl;
        std::cout << "TCP Packets: " << tcp_count << std::endl;
        std::cout << "UDP Packets: " << udp_count << std::endl;
        std::cout << "ICMP Packets: " << icmp_count << std::endl;
        std::cout << "Other Packets: " << other_count << std::endl;
        std::cout << "Filtered Out: " << filtered_count << std::endl;
        std::cout << "Total Displayed: " << (tcp_count + udp_count + icmp_count + other_count) << std::endl;
    }

    ~PacketAnalyzer() {
#ifdef _WIN32
        if(sock != INVALID_SOCKET) {
            closesocket(sock);
            WSACleanup();
        }
#else
        if(sock >= 0) {
            close(sock);
        }
#endif
    }
};

void printUsage(const char* prog_name) {
    std::cout << "Usage: " << prog_name << " [options]" << std::endl;
    std::cout << "\nOptions:" << std::endl;
    std::cout << "  -n <num>              Number of packets to capture (default: 10)" << std::endl;
    std::cout << "  -f <filter>           Add packet filter (can use multiple times)" << std::endl;
    std::cout << "\nFilter formats:" << std::endl;
    std::cout << "  protocol=tcp          Filter by protocol (tcp/udp/icmp)" << std::endl;
    std::cout << "  src=192.168.1.1       Filter by source IP" << std::endl;
    std::cout << "  dst=192.168.1.1       Filter by destination IP" << std::endl;
    std::cout << "  sport=80              Filter by source port" << std::endl;
    std::cout << "  dport=443             Filter by destination port" << std::endl;
    std::cout << "  port=22               Filter by port (source or dest)" << std::endl;
    std::cout << "\nExamples:" << std::endl;
#ifdef _WIN32
    std::cout << "  " << prog_name << " -n 20 -f protocol=tcp" << std::endl;
    std::cout << "  " << prog_name << " -f port=80 -f protocol=tcp" << std::endl;
    std::cout << "\nNote: Must run as Administrator on Windows!" << std::endl;
#else
    std::cout << "  sudo " << prog_name << " -n 20 -f protocol=tcp" << std::endl;
    std::cout << "  sudo " << prog_name << " -f port=80 -f protocol=tcp" << std::endl;
#endif
}

int main(int argc, char *argv[]) {
    int num_packets = 10;
    std::vector<std::string> filter_strings;

    for(int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if(arg == "-n" && i + 1 < argc) {
            num_packets = std::atoi(argv[++i]);
            if(num_packets <= 0) num_packets = 10;
        } else if(arg == "-f" && i + 1 < argc) {
            filter_strings.push_back(argv[++i]);
        } else if(arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 0;
        }
    }

    std::cout << "Cross-Platform Network Packet Analyzer" << std::endl;
#ifdef _WIN32
    std::cout << "Running on Windows" << std::endl;
#else
    std::cout << "Running on Linux/Unix" << std::endl;
#endif
    std::cout << "Capturing " << num_packets << " packets..." << std::endl;
    std::cout << std::endl;

    PacketAnalyzer analyzer;
    if(!analyzer.initialize()) {
        return 1;
    }

    for(const auto& filter_str : filter_strings) {
        analyzer.addFilter(filter_str);
    }

    if(filter_strings.empty()) {
        std::cout << "No filters applied - capturing all packets" << std::endl;
    }

    analyzer.capturePackets(num_packets);

    return 0;
}
