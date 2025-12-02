#include "StaticRouter.h"

#include <spdlog/spdlog.h>
#include <cstring>

#include "protocol.h"
#include "utils.h"

StaticRouter::StaticRouter(
    std::unique_ptr<ArpCache> arpCache, 
    std::shared_ptr<IRoutingTable> routingTable,
    std::shared_ptr<IPacketSender> packetSender)
    : routingTable(routingTable)
    , packetSender(packetSender)
    , arpCache(std::move(arpCache))
{
}

void StaticRouter::handlePacket(std::vector<uint8_t> packet, std::string iface)
{
    std::unique_lock lock(mutex);

    if (packet.size() < sizeof(sr_ethernet_hdr_t))
    {
        spdlog::error("Packet is too small to contain an Ethernet header.");
        return;
    }

    // TODO: Your code below
    sr_ethernet_hdr *  eth_hdr = reinterpret_cast<sr_ethernet_hdr*>(packet.data());
    sr_ip_hdr * ip_hdr = reinterpret_cast<sr_ip_hdr*>(packet.data() + sizeof(sr_ethernet_hdr_t));
    uint16_t calc_cksum = cksum(packet.data()+sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr));
    if(ip_hdr->ip_sum != calc_cksum){
        return;
    }
    RoutingInterface routing_interface = routingTable->getRoutingInterface(iface);
    if(routing_interface.ip != ip_hdr->ip_dst){
        forwardPacket(eth_hdr, ip_hdr, packet);
    }

}

void StaticRouter::forwardPacket(sr_ethernet_hdr *  eth_hdr, sr_ip_hdr * ip_hdr, const std::vector<uint8_t> &packet){
    ip_hdr->ip_ttl--;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(ip_hdr));
    routingTable->getRoutingEntry(ip_hdr->ip_dst); 
}

