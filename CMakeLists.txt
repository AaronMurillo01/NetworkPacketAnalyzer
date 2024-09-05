cmake_minimum_required(VERSION 3.10)
project(NetworkPacketAnalyzer)

set(CMAKE_CXX_STANDARD 17)

find_package(PCAP REQUIRED)

add_executable(packet_analyzer src/main.cpp src/packet_analyzer.cpp)
target_include_directories(packet_analyzer PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(packet_analyzer PRIVATE ${PCAP_LIBRARIES})