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
    if(ntohs(eth_hdr->ether_type)==ethertype_arp){
        handleARP(packet, iface);
    } else {
        handleIP(packet, iface);
    }

}
void StaticRouter::handleIP(std::vector<uint8_t> &packet, std::string &iface)
{
    sr_ethernet_hdr *  eth_hdr = reinterpret_cast<sr_ethernet_hdr*>(packet.data());
    sr_ip_hdr * ip_hdr = reinterpret_cast<sr_ip_hdr*>(packet.data() + sizeof(sr_ethernet_hdr_t));
    uint16_t real_cksum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    uint16_t calc_cksum = cksum(packet.data()+sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr));
    if(real_cksum != calc_cksum){
        return;
    }
    RoutingInterface routing_interface = routingTable->getRoutingInterface(iface);
    if(htonl(routing_interface.ip) != ip_hdr->ip_dst){
        forwardIPPacket(packet, iface);
    } else {
        if(ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp){
            sendICMPT3Unreachable(packet, iface, 3);//port unreachable
        } else {
            sr_icmp_hdr * icmp_hdr = reinterpret_cast<sr_icmp_hdr*>(packet.data()+sizeof(sr_ethernet_hdr)+sizeof(sr_ip_hdr));
            if(icmp_hdr->icmp_type == 8 & icmp_hdr->icmp_code == 0){
                sendEchoReply(packet, iface);
            }
        }
    }
}
void StaticRouter::handleARP(std::vector<uint8_t> &packet, std::string &iface)
{
    sr_ethernet_hdr *  eth_hdr = reinterpret_cast<sr_ethernet_hdr*>(packet.data());
    sr_arp_hdr * arp_hdr = reinterpret_cast<sr_arp_hdr*>(packet.data() + sizeof(sr_ethernet_hdr_t));
    RoutingInterface routing_interface = routingTable->getRoutingInterface(iface);
    if(arp_hdr->ar_tip == routing_interface.ip){
        spdlog::info(
            "Received ARP reply on iface {}: from IP {} to IP {}",
            iface,
            ntohl(arp_hdr->ar_sip),
            ntohl(arp_hdr->ar_tip),
            (ntohs(arp_hdr->ar_op) == arp_op_request ? "request" : "reply")
        );
        mac_addr sender_mac;
        std::copy(arp_hdr->ar_sha, arp_hdr->ar_sha + 6, sender_mac.begin());
        if(ntohs(arp_hdr->ar_op)==arp_op_request){
                generateARPReply(sender_mac, arp_hdr->ar_sip, iface);
        } else {
                mac_addr sender_mac;
                std::copy(arp_hdr->ar_sha, arp_hdr->ar_sha + 6, sender_mac.begin());
                arpCache->addEntry(arp_hdr->ar_sip, sender_mac); 
        }
    } else {
        spdlog::info(
            "Received unrequited ARP packet on iface {}: from IP {} to IP {} (type={})",
            iface,
            ntohl(arp_hdr->ar_sip),
            ntohl(arp_hdr->ar_tip),
            (ntohs(arp_hdr->ar_op) == arp_op_request ? "request" : "reply")
        );
    }
}

void StaticRouter::generateARPReply(mac_addr target_mac, uint32_t target_ip, std::string&iface){
    std::vector<uint8_t> reply_packet(sizeof(sr_ethernet_hdr) + sizeof(sr_arp_hdr));
    sr_ethernet_hdr *  eth_hdr = reinterpret_cast<sr_ethernet_hdr*>(reply_packet.data());
    sr_arp_hdr * arp_hdr = reinterpret_cast<sr_arp_hdr*>(reply_packet.data() + sizeof(sr_ethernet_hdr_t));
    
    eth_hdr->ether_type = htons(ethertype_arp);
    RoutingInterface routingInterace = routingTable->getRoutingInterface(iface);
    mac_addr source_mac = routingInterace.mac;
    std::copy(
        source_mac.begin(),
        source_mac.end(),
        eth_hdr->ether_shost
    );
    std::copy(
        target_mac.begin(),
        target_mac.end(),
        eth_hdr->ether_dhost
    );

    arp_hdr->ar_hrd = htons(1);            
    arp_hdr->ar_pro = htons(0x0800);       
    arp_hdr->ar_hln = 6;
    arp_hdr->ar_pln = 4;
    arp_hdr->ar_op  = htons(2);        
    std::copy(
        source_mac.begin(),
        source_mac.end(),
        arp_hdr->ar_sha
    );
    arp_hdr->ar_sip = routingInterace.ip;
    std::copy(
        target_mac.begin(),
        target_mac.end(),
        arp_hdr->ar_tha
    );
    arp_hdr->ar_tip = target_ip;

    packetSender->sendPacket(reply_packet, iface);
}

void StaticRouter::forwardIPPacket(std::vector<uint8_t> &packet, std::string &iface){
    sr_ethernet_hdr *  eth_hdr = reinterpret_cast<sr_ethernet_hdr*>(packet.data());
    sr_ip_hdr * ip_hdr = reinterpret_cast<sr_ip_hdr*>(packet.data() + sizeof(sr_ethernet_hdr_t));
    ip_hdr->ip_ttl--;

    if(ip_hdr->ip_ttl==0){
        sendICMPT11Unreachable(packet, iface); //time exceeded
        return;
    }
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr));
    auto optEntry = routingTable->getRoutingEntry(ip_hdr->ip_dst); 
    if(!optEntry.has_value()){
        sendICMPT3Unreachable(packet, iface, 0);//Dest net unreachable
        return;
    }

    auto optMacAddr = arpCache->getEntry(optEntry.value().gateway); 
    if(!optMacAddr.has_value()){
        arpCache->queuePacket(optEntry.value().gateway, packet, iface);
    } else {
        auto mac = optMacAddr.value();
        std::copy(eth_hdr->ether_dhost,
                    eth_hdr->ether_dhost + ETHER_ADDR_LEN,
                    eth_hdr->ether_shost);
        std::copy(mac.begin(), mac.end(), eth_hdr->ether_dhost);

        packetSender->sendPacket(packet, iface);
    }
}

void StaticRouter::sendEchoReply(const Packet& originalPacket, const std::string& iface){

    const sr_ethernet_hdr_t* origEth = reinterpret_cast<const sr_ethernet_hdr_t*>(originalPacket.data());
    const sr_ip_hdr_t* origIp = reinterpret_cast<const sr_ip_hdr_t*>(
        originalPacket.data() + sizeof(sr_ethernet_hdr_t));

    std::vector<uint8_t> icmpPacket(originalPacket.size());
    sr_ethernet_hdr * ethHdr = reinterpret_cast<sr_ethernet_hdr*>(icmpPacket.data());
    sr_ip_hdr * ipHdr = reinterpret_cast<sr_ip_hdr*>(icmpPacket.data()+sizeof(sr_ethernet_hdr));
    sr_icmp_hdr_t* icmpHdr = reinterpret_cast<sr_icmp_hdr_t*>(
        icmpPacket.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    auto ifaceInfo = routingTable->getRoutingInterface(iface);
    std::memcpy(ethHdr->ether_dhost, origEth->ether_shost, ETHER_ADDR_LEN);
    std::memcpy(ethHdr->ether_shost, ifaceInfo.mac.data(), ETHER_ADDR_LEN);
    ethHdr->ether_type = htons(ethertype_ip);
    ipHdr->ip_v = 4;
    ipHdr->ip_hl = 5;
    ipHdr->ip_tos = 0;
    ipHdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    ipHdr->ip_id = 0;
    ipHdr->ip_off = htons(IP_DF);
    ipHdr->ip_ttl = 65;
    ipHdr->ip_p = ip_protocol_icmp;
    ipHdr->ip_src = ifaceInfo.ip;
    ipHdr->ip_dst = origIp->ip_src;
    ipHdr->ip_sum = 0;
    ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));
    icmpHdr->icmp_type = 0;
    icmpHdr->icmp_code = 0;
    spdlog::info(
            "Send echo reply from iface {}: from IP {} to IP {}",
            iface,
            ntohl(ipHdr->ip_src),
            ntohl(ipHdr->ip_dst)
        );

    uint8_t* icmp_payload = reinterpret_cast<uint8_t*>(icmpHdr) + sizeof(sr_icmp_hdr) + 4;
    std::copy(
        originalPacket.begin() +sizeof(sr_ethernet_hdr) + sizeof(sr_ip_hdr) + sizeof(sr_icmp_hdr),
        originalPacket.end(),
        icmp_payload
    );

    icmpHdr->icmp_sum = 0;
    icmpHdr->icmp_sum = cksum(icmpPacket.data()+sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr),
                               icmpPacket.size() - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr));

    packetSender->sendPacket(icmpPacket, iface);
}


void StaticRouter::sendICMPT3Unreachable(const Packet& originalPacket, const std::string& iface, uint8_t code) {
    if (originalPacket.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        return;
    }

    const sr_ethernet_hdr_t* origEth = reinterpret_cast<const sr_ethernet_hdr_t*>(originalPacket.data());
    const sr_ip_hdr_t* origIp = reinterpret_cast<const sr_ip_hdr_t*>(
        originalPacket.data() + sizeof(sr_ethernet_hdr_t));
    size_t packetLen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    std::vector<uint8_t> icmpPacket(packetLen);
    
    sr_ethernet_hdr_t* ethHdr = reinterpret_cast<sr_ethernet_hdr_t*>(icmpPacket.data());
    sr_ip_hdr_t* ipHdr = reinterpret_cast<sr_ip_hdr_t*>(icmpPacket.data() + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t* icmpHdr = reinterpret_cast<sr_icmp_t3_hdr_t*>(
        icmpPacket.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    try {
        auto ifaceInfo = routingTable->getRoutingInterface(iface);
        std::memcpy(ethHdr->ether_dhost, origEth->ether_shost, ETHER_ADDR_LEN);
        std::memcpy(ethHdr->ether_shost, ifaceInfo.mac.data(), ETHER_ADDR_LEN);
        ethHdr->ether_type = htons(ethertype_ip);
        ipHdr->ip_v = 4;
        ipHdr->ip_hl = 5;
        ipHdr->ip_tos = 0;
        ipHdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        ipHdr->ip_id = 0;
        ipHdr->ip_off = htons(IP_DF);
        ipHdr->ip_ttl = 65;
        ipHdr->ip_p = ip_protocol_icmp;
        ipHdr->ip_src = ifaceInfo.ip;
        ipHdr->ip_dst = origIp->ip_src;
        ipHdr->ip_sum = 0;
        ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));
        icmpHdr->icmp_type = 3;
        icmpHdr->icmp_code = 1;
        icmpHdr->unused = 0;
        icmpHdr->next_mtu = 0;
        size_t dataToCopy = std::min(sizeof(icmpHdr->data),
        originalPacket.size() - sizeof(sr_ethernet_hdr_t));
        std::memcpy(icmpHdr->data, origIp, dataToCopy);
        
        icmpHdr->icmp_sum = 0;
        icmpHdr->icmp_sum = cksum(icmpHdr, sizeof(sr_icmp_t3_hdr_t));
        
        packetSender->sendPacket(icmpPacket, iface);
    } catch (const std::exception& e) {
        spdlog::error("Failed to send ICMP host unreachable: {}", e.what());
    }
}

void StaticRouter::sendICMPT11Unreachable(const Packet& originalPacket, const std::string& iface) {
    if (originalPacket.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        return;
    }

    const sr_ethernet_hdr_t* origEth = reinterpret_cast<const sr_ethernet_hdr_t*>(originalPacket.data());
    const sr_ip_hdr_t* origIp = reinterpret_cast<const sr_ip_hdr_t*>(
        originalPacket.data() + sizeof(sr_ethernet_hdr_t));
    size_t packetLen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    std::vector<uint8_t> icmpPacket(packetLen);
    
    sr_ethernet_hdr_t* ethHdr = reinterpret_cast<sr_ethernet_hdr_t*>(icmpPacket.data());
    sr_ip_hdr_t* ipHdr = reinterpret_cast<sr_ip_hdr_t*>(icmpPacket.data() + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t* icmpHdr = reinterpret_cast<sr_icmp_hdr_t*>(
        icmpPacket.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    try {
        auto ifaceInfo = routingTable->getRoutingInterface(iface);
        std::memcpy(ethHdr->ether_dhost, origEth->ether_shost, ETHER_ADDR_LEN);
        std::memcpy(ethHdr->ether_shost, ifaceInfo.mac.data(), ETHER_ADDR_LEN);
        ethHdr->ether_type = htons(ethertype_ip);
        ipHdr->ip_v = 4;
        ipHdr->ip_hl = 5;
        ipHdr->ip_tos = 0;
        ipHdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        ipHdr->ip_id = 0;
        ipHdr->ip_off = htons(IP_DF);
        ipHdr->ip_ttl = 65;
        ipHdr->ip_p = ip_protocol_icmp;
        ipHdr->ip_src = ifaceInfo.ip;
        ipHdr->ip_dst = origIp->ip_src;
        ipHdr->ip_sum = 0;
        ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));
        icmpHdr->icmp_type = 11;
        icmpHdr->icmp_code = 0;
        
        icmpHdr->icmp_sum = 0;
        icmpHdr->icmp_sum = cksum(icmpHdr, sizeof(sr_icmp_hdr_t));
        
        packetSender->sendPacket(icmpPacket, iface);
    } catch (const std::exception& e) {
        spdlog::error("Failed to send ICMP host unreachable: {}", e.what());
    }
}

