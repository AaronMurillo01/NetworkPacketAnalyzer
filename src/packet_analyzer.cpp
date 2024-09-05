#include "packet_analyzer.h"
#include <iostream>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

PacketAnalyzer::PacketAnalyzer() : handle(nullptr) {}

PacketAnalyzer::~PacketAnalyzer() {
    if (handle) {
        pcap_close(handle);
    }
}

bool PacketAnalyzer::openInterface(const std::string& interface_name) {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(interface_name.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open device " << interface_name << ": " << errbuf << std::endl;
        return false;
    }
    return true;
}

void PacketAnalyzer::startCapture(int num_packets) {
    if (!handle) {
        std::cerr << "No interface opened. Call openInterface() first." << std::endl;
        return;
    }

    pcap_loop(handle, num_packets, packetHandler, reinterpret_cast<u_char*>(this));
}

void PacketAnalyzer::packetHandler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    PacketAnalyzer* analyzer = reinterpret_cast<PacketAnalyzer*>(user_data);
    analyzer->processPacket(pkthdr, packet);
}

void PacketAnalyzer::processPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct ip* ip_header = (struct ip*)(packet + 14); // Skip Ethernet header
    
    std::cout << "Packet captured. Length: " << pkthdr->len << " bytes" << std::endl;
    std::cout << "Source IP: " << inet_ntoa(ip_header->ip_src) << std::endl;
    std::cout << "Destination IP: " << inet_ntoa(ip_header->ip_dst) << std::endl;

    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + 14 + ip_header->ip_hl * 4);
        std::cout << "Protocol: TCP" << std::endl;
        std::cout << "Source Port: " << ntohs(tcp_header->th_sport) << std::endl;
        std::cout << "Destination Port: " << ntohs(tcp_header->th_dport) << std::endl;
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr* udp_header = (struct udphdr*)(packet + 14 + ip_header->ip_hl * 4);
        std::cout << "Protocol: UDP" << std::endl;
        std::cout << "Source Port: " << ntohs(udp_header->uh_sport) << std::endl;
        std::cout << "Destination Port: " << ntohs(udp_header->uh_dport) << std::endl;
    } else {
        std::cout << "Protocol: Other" << std::endl;
    }

    std::cout << "------------------------" << std::endl;
}