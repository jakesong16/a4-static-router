#ifndef ARPCACHE_H
#define ARPCACHE_H

#include <chrono>
#include <unordered_map>
#include <thread>
#include <optional>
#include <memory>
#include <mutex>
#include <vector>  // ADD THIS LINE
#include <queue>

#include "IPacketSender.h"
#include "RouterTypes.h"
#include "IRoutingTable.h"

struct ArpEntry {
    std::chrono::steady_clock::time_point timeAdded;
    mac_addr mac;
};

struct PendingPacket {
    Packet packet;
    std::string iFaceFrom;
    std::string iFaceTo;
};

struct ArpRequest {
    std::vector<PendingPacket> packets;
    std::chrono::steady_clock::time_point lastSent;
    int timesSent;
    
    ArpRequest() : timesSent(0) {}
};

class ArpCache {
public:
    ArpCache(
        std::chrono::milliseconds entryTimeout,
        std::chrono::milliseconds tickInterval,
        std::chrono::milliseconds resendInterval,
        std::shared_ptr<IPacketSender> packetSender, 
        std::shared_ptr<IRoutingTable> routingTable);

    ~ArpCache();

    void tick();

    void addEntry(uint32_t ip, const mac_addr& mac);

    std::optional<mac_addr> getEntry(uint32_t ip);

    void queuePacket(uint32_t ip, const Packet& packet, const std::string& iface);

private:
    void loop();
    void sendArpRequest(uint32_t targetIp, const std::string& iface);  // ADD THIS LINE
    void sendICMPHostUnreachable(Packet& originalPacket, const std::string& iface);  // ADD THIS LINE

    std::chrono::milliseconds entryTimeout;
    std::chrono::milliseconds tickInterval;
    std::chrono::milliseconds resendInterval;

    std::unique_ptr<std::thread> thread;
    std::atomic<bool> shutdown = false;

    std::mutex mutex;
    std::shared_ptr<IPacketSender> packetSender;
    std::shared_ptr<IRoutingTable> routingTable;

    std::unordered_map<ip_addr, ArpEntry> entries;
    std::unordered_map<ip_addr, ArpRequest> pendingRequests;  // ADD THIS LINE
};

#endif //ARPCACHE_H