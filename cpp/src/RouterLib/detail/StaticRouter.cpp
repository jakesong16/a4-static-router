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
    uint16_t real_cksum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    uint16_t calc_cksum = cksum(packet.data()+sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr));
    if(real_cksum != calc_cksum){
        return;
    }
    RoutingInterface routing_interface = routingTable->getRoutingInterface(iface);
    if(routing_interface.ip != ip_hdr->ip_dst){
        forwardPacket(packet, iface);
    }

}

void StaticRouter::forwardPacket(std::vector<uint8_t> &packet, std::string &iface){
    sr_ethernet_hdr *  eth_hdr = reinterpret_cast<sr_ethernet_hdr*>(packet.data());
    sr_ip_hdr * ip_hdr = reinterpret_cast<sr_ip_hdr*>(packet.data() + sizeof(sr_ethernet_hdr_t));
    ip_hdr->ip_ttl--;

    if(ip_hdr->ip_ttl==0){
        sendTTLEM(eth_hdr, ip_hdr, iface);
        return;
    }
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr));
    auto optEntry = routingTable->getRoutingEntry(ip_hdr->ip_dst); 
    if(!optEntry.has_value()){
        //TODO: handle no valid route
        return;
    }

    auto optMacAddr = arpCache->getEntry(optEntry.value().gateway); //replace with optentry
    if(!optMacAddr.has_value()){
        arpCache->queuePacket(optEntry.value().gateway, packet, iface);
    } else {
        auto mac = optMacAddr.value();
        std::copy(mac.begin(), mac.end(), eth_hdr->ether_dhost);
        packetSender->sendPacket(packet, iface);
    }
}

void StaticRouter::createICMPHeaderTemplate(sr_ethernet_hdr *  eth_hdr, sr_ip_hdr * ip_hdr, std::vector<uint8_t> &icmp_packet, std::string &iface){
    
    
    sr_ip_hdr *  icmp_ip_hdr = reinterpret_cast<sr_ip_hdr*>(icmp_packet.data()+sizeof(sr_ethernet_hdr));
    // ICMP_ip_hdr.ip_tos 
    icmp_ip_hdr->ip_v  = 4;   
    icmp_ip_hdr->ip_hl = 5;
    icmp_ip_hdr->ip_tos = 0;
    icmp_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr) + sizeof(sr_icmp_hdr) + 4 + 8);
    icmp_ip_hdr->ip_id = 0;
    icmp_ip_hdr->ip_off = 0;
    icmp_ip_hdr->ip_ttl = 64;
    icmp_ip_hdr->ip_p = ip_protocol_icmp;
    icmp_ip_hdr->ip_src = routingTable->getRoutingInterface(iface).ip;
    icmp_ip_hdr->ip_dst = ip_hdr->ip_src;

    

    sr_ethernet_hdr *  icmp_eth_hdr = reinterpret_cast<sr_ethernet_hdr*>(icmp_packet.data());
    mac_addr source_mac = routingTable->getRoutingInterface(iface).mac;
    std::copy(source_mac.begin(), source_mac.end(), icmp_eth_hdr->ether_shost);
    // std::copy(std::begin(eth_hdr->ether_shost),
    //       std::end(eth_hdr->ether_shost),
    //       ICMP_eth_hdr.ether_dhost);
    icmp_eth_hdr->ether_type = ethertype_ip;

}

void StaticRouter::sendTTLEM(sr_ethernet_hdr *  eth_hdr, sr_ip_hdr * ip_hdr, std::string &iface){
    std::vector<uint8_t> icmp_packet(sizeof(sr_ethernet_hdr)+sizeof(sr_ip_hdr)+sizeof(sr_icmp_hdr) + 12, 0);
    sr_icmp_hdr * ICMP_icmp_hdr = reinterpret_cast<sr_icmp_hdr*>(icmp_packet.data()+sizeof(sr_ethernet_hdr)+sizeof(sr_ip_hdr));
    ICMP_icmp_hdr->icmp_type = 11;
    ICMP_icmp_hdr->icmp_code = 0;
    ICMP_icmp_hdr->icmp_sum = 0;
    ICMP_icmp_hdr->icmp_sum = cksum(icmp_packet.data()+sizeof(sr_ethernet_hdr_t) +sizeof(sr_ip_hdr), sizeof(sr_icmp_hdr));

    uint8_t* icmp_payload = icmp_packet.data()
                        + sizeof(sr_ethernet_hdr)
                        + sizeof(sr_ip_hdr)
                        + sizeof(sr_icmp_hdr)
                        + 4; 
    std::copy(
        reinterpret_cast<uint8_t*>(ip_hdr),
        reinterpret_cast<uint8_t*>(ip_hdr) + sizeof(sr_ip_hdr),
        icmp_payload
    );
    uint8_t* original_payload = reinterpret_cast<uint8_t*>(ip_hdr) + sizeof(sr_ip_hdr);
    std::copy(
        original_payload,
        original_payload + 8,
        icmp_payload + sizeof(sr_ip_hdr) // write after the 20 bytes
    );

    forwardPacket(icmp_packet, iface);
}

