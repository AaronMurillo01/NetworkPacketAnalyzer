#include "packet_analyzer.h"
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>" << std::endl;
        return 1;
    }

    std::string interface_name = argv[1];
    PacketAnalyzer analyzer;

    if (!analyzer.openInterface(interface_name)) {
        return 1;
    }

    std::cout << "Starting packet capture on interface " << interface_name << std::endl;
    analyzer.startCapture(); // Capture indefinitely

    return 0;
}