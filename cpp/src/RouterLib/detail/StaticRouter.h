#ifndef STATICROUTER_H
#define STATICROUTER_H
#include <vector>
#include <memory>
#include <mutex>

#include "ArpCache.h"
#include "IPacketSender.h"
#include "IRoutingTable.h"
#include "IStaticRouter.h"

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

    void handleEcho(const std::vector<uint8_t> &packet);
    void forwardPacket(sr_ethernet_hdr *  eth_hdr, sr_ip_hdr * ip_hdr, const std::vector<uint8_t> &packet);
};


#endif //STATICROUTER_H
