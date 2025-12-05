#ifndef STATICROUTER_H
#define STATICROUTER_H
#include <vector>
#include <memory>
#include <mutex>

#include "ArpCache.h"
#include "IPacketSender.h"
#include "IRoutingTable.h"
#include "IStaticRouter.h"
#include "protocol.h"

class StaticRouter : public IStaticRouter {
public:
    StaticRouter(
        std::unique_ptr<ArpCache> arpCache, 
        std::shared_ptr<IRoutingTable> routingTable,
        std::shared_ptr<IPacketSender> packetSender);

    virtual void handlePacket(std::vector<uint8_t> packet, std::string iface) override;

private:
    std::mutex mutex;

    std::shared_ptr<IRoutingTable> routingTable;
    std::shared_ptr<IPacketSender> packetSender;

    std::unique_ptr<ArpCache> arpCache;


    void handleIP(std::vector<uint8_t> &packet, std::string &iface);
    void handleARP(std::vector<uint8_t> &packet, std::string &iface);
    void forwardIPPacket(std::vector<uint8_t> &packet, std::string &iface);
    void forwardARPPacket(std::vector<uint8_t> &packet, std::string &iface);
    void generateARPReply(mac_addr target_mac, uint32_t target_ip, std::string &iface);
    void sendEchoReply(const Packet& originalPacket, const std::string& iface);
    void sendICMPT3Unreachable(const Packet& originalPacket, const std::string& iface, uint8_t code);
    void sendICMPT11Unreachable(const Packet& originalPacket, const std::string& iface);
};


#endif //STATICROUTER_H
