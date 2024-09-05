#pragma once

#include <pcap.h>
#include <string>

class PacketAnalyzer {
public:
    PacketAnalyzer();
    ~PacketAnalyzer();

    bool openInterface(const std::string& interface_name);
    void startCapture(int num_packets = -1);  // -1 means capture indefinitely

private:
    pcap_t* handle;
    static void packetHandler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    void processPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet);
};