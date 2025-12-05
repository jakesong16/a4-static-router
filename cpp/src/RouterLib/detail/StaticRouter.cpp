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

    sr_ethernet_hdr_t* eth_hdr = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    uint16_t ether_type = ntohs(eth_hdr->ether_type);
    
    if(ether_type == ethertype_arp){
        handleARP(packet, iface);
    } else if(ether_type == ethertype_ip){
        handleIP(packet, iface);
    }
}

void StaticRouter::handleIP(std::vector<uint8_t> &packet, std::string &iface)
{
    if (packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        return;
    }

    sr_ethernet_hdr_t* eth_hdr = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    sr_ip_hdr_t* ip_hdr = reinterpret_cast<sr_ip_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
    
    uint16_t real_cksum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    uint16_t calc_cksum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    ip_hdr->ip_sum = real_cksum;
    
    if(real_cksum != calc_cksum){
        spdlog::debug("IP checksum mismatch, dropping packet");
        return;
    }
    
    bool destForRouter = false;
    for (const auto& [ifaceName, ifaceInfo] : routingTable->getRoutingInterfaces()) {
        if (ifaceInfo.ip == ip_hdr->ip_dst) {
            destForRouter = true;
            break;
        }
    }

    if(destForRouter){
        if(ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp){
            sendICMPT3Unreachable(packet, iface, 3);
        } else if(ip_hdr->ip_p == ip_protocol_icmp){
            if (packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)) {
                return;
            }
            sr_icmp_hdr_t* icmp_hdr = reinterpret_cast<sr_icmp_hdr_t*>(
                packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            
            uint16_t real_icmp_cksum = icmp_hdr->icmp_sum;
            icmp_hdr->icmp_sum = 0;
            uint16_t calc_icmp_cksum = cksum(icmp_hdr, 
                packet.size() - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
            icmp_hdr->icmp_sum = real_icmp_cksum;
            
            if (real_icmp_cksum != calc_icmp_cksum) {
                spdlog::debug("ICMP checksum mismatch, dropping packet");
                return;
            }
            
            if(icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0){
                sendEchoReply(packet, iface);
            }
        }
    } else {
        forwardIPPacket(packet, iface);
    }
}

void StaticRouter::handleARP(std::vector<uint8_t> &packet, std::string &iface)
{
    if (packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
        return;
    }

    sr_ethernet_hdr_t* eth_hdr = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    sr_arp_hdr_t* arp_hdr = reinterpret_cast<sr_arp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
    
    try {
        RoutingInterface routing_interface = routingTable->getRoutingInterface(iface);
        
        if(arp_hdr->ar_tip == routing_interface.ip){
            mac_addr sender_mac;
            std::copy(arp_hdr->ar_sha, arp_hdr->ar_sha + ETHER_ADDR_LEN, sender_mac.begin());
            
            if(ntohs(arp_hdr->ar_op) == arp_op_request){
                generateARPReply(sender_mac, arp_hdr->ar_sip, iface);
            } else if(ntohs(arp_hdr->ar_op) == arp_op_reply){
                arpCache->addEntry(arp_hdr->ar_sip, sender_mac); 
            }
        }
    } catch (const std::exception& e) {
        spdlog::error("Error in handleARP: {}", e.what());
    }
}

void StaticRouter::generateARPReply(mac_addr target_mac, uint32_t target_ip, std::string& iface){
    try {
        std::vector<uint8_t> reply_packet(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
        sr_ethernet_hdr_t* eth_hdr = reinterpret_cast<sr_ethernet_hdr_t*>(reply_packet.data());
        sr_arp_hdr_t* arp_hdr = reinterpret_cast<sr_arp_hdr_t*>(reply_packet.data() + sizeof(sr_ethernet_hdr_t));
        
        RoutingInterface routingInterface = routingTable->getRoutingInterface(iface);
        
        std::memcpy(eth_hdr->ether_shost, routingInterface.mac.data(), ETHER_ADDR_LEN);
        std::memcpy(eth_hdr->ether_dhost, target_mac.data(), ETHER_ADDR_LEN);
        eth_hdr->ether_type = htons(ethertype_arp);

        arp_hdr->ar_hrd = htons(arp_hrd_ethernet);            
        arp_hdr->ar_pro = htons(ethertype_ip);       
        arp_hdr->ar_hln = ETHER_ADDR_LEN;
        arp_hdr->ar_pln = 4;
        arp_hdr->ar_op = htons(arp_op_reply);        
        
        std::memcpy(arp_hdr->ar_sha, routingInterface.mac.data(), ETHER_ADDR_LEN);
        arp_hdr->ar_sip = routingInterface.ip;
        std::memcpy(arp_hdr->ar_tha, target_mac.data(), ETHER_ADDR_LEN);
        arp_hdr->ar_tip = target_ip;

        packetSender->sendPacket(reply_packet, iface);
    } catch (const std::exception& e) {
        spdlog::error("Error in generateARPReply: {}", e.what());
    }
}

void StaticRouter::forwardIPPacket(std::vector<uint8_t> &packet, std::string &iface){
    sr_ethernet_hdr_t* eth_hdr = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    sr_ip_hdr_t* ip_hdr = reinterpret_cast<sr_ip_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
    
    if(ip_hdr->ip_ttl <= 1){
        sendICMPT11Unreachable(packet, iface);
        return;
    }
    
    ip_hdr->ip_ttl--;
    
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    
    auto optEntry = routingTable->getRoutingEntry(ip_hdr->ip_dst); 
    if(!optEntry.has_value()){
        ip_hdr->ip_ttl++;
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
        sendICMPT3Unreachable(packet, iface, 0);
        return;
    }
    
    std::string outIface = optEntry.value().iface;
    uint32_t nextHopIP = optEntry.value().gateway;
    
    auto optMacAddr = arpCache->getEntry(nextHopIP); 
    if(!optMacAddr.has_value()){
        arpCache->queuePacket(nextHopIP, packet, iface);
    } else {
        try {
            auto outIfaceInfo = routingTable->getRoutingInterface(outIface);
            
            std::memcpy(eth_hdr->ether_shost, outIfaceInfo.mac.data(), ETHER_ADDR_LEN);
            std::memcpy(eth_hdr->ether_dhost, optMacAddr.value().data(), ETHER_ADDR_LEN);

            packetSender->sendPacket(packet, outIface);
        } catch (const std::exception& e) {
            spdlog::error("Error forwarding packet: {}", e.what());
        }
    }
}

void StaticRouter::sendEchoReply(const Packet& originalPacket, const std::string& iface){
    const sr_ethernet_hdr_t* origEth = reinterpret_cast<const sr_ethernet_hdr_t*>(originalPacket.data());
    const sr_ip_hdr_t* origIp = reinterpret_cast<const sr_ip_hdr_t*>(
        originalPacket.data() + sizeof(sr_ethernet_hdr_t));

    std::vector<uint8_t> icmpPacket = originalPacket;
    
    sr_ethernet_hdr_t* ethHdr = reinterpret_cast<sr_ethernet_hdr_t*>(icmpPacket.data());
    sr_ip_hdr_t* ipHdr = reinterpret_cast<sr_ip_hdr_t*>(icmpPacket.data() + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t* icmpHdr = reinterpret_cast<sr_icmp_hdr_t*>(
        icmpPacket.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    
    try {
        auto ifaceInfo = routingTable->getRoutingInterface(iface);

        std::memcpy(ethHdr->ether_dhost, origEth->ether_shost, ETHER_ADDR_LEN);
        std::memcpy(ethHdr->ether_shost, ifaceInfo.mac.data(), ETHER_ADDR_LEN);
        ethHdr->ether_type = htons(ethertype_ip);
        
        ipHdr->ip_ttl = 64;
        ipHdr->ip_src = origIp->ip_dst;
        ipHdr->ip_dst = origIp->ip_src;
        ipHdr->ip_sum = 0;
        ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));
        
        icmpHdr->icmp_type = 0;
        icmpHdr->icmp_code = 0;
        icmpHdr->icmp_sum = 0;
        icmpHdr->icmp_sum = cksum(icmpHdr, 
            icmpPacket.size() - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

        packetSender->sendPacket(icmpPacket, iface);
    } catch (const std::exception& e) {
        spdlog::error("Error in sendEchoReply: {}", e.what());
    }
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
        ipHdr->ip_ttl = 64;
        ipHdr->ip_p = ip_protocol_icmp;
        ipHdr->ip_src = ifaceInfo.ip;
        ipHdr->ip_dst = origIp->ip_src;
        ipHdr->ip_sum = 0;
        ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));
        
        icmpHdr->icmp_type = 3;
        icmpHdr->icmp_code = code;
        icmpHdr->unused = 0;
        icmpHdr->next_mtu = 0;
        
        size_t dataToCopy = std::min(sizeof(icmpHdr->data),
            originalPacket.size() - sizeof(sr_ethernet_hdr_t));
        std::memcpy(icmpHdr->data, origIp, dataToCopy);
        
        icmpHdr->icmp_sum = 0;
        icmpHdr->icmp_sum = cksum(icmpHdr, sizeof(sr_icmp_t3_hdr_t));
        
        packetSender->sendPacket(icmpPacket, iface);
    } catch (const std::exception& e) {
        spdlog::error("Error in sendICMPT3Unreachable: {}", e.what());
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
        ipHdr->ip_ttl = 64;
        ipHdr->ip_p = ip_protocol_icmp;
        ipHdr->ip_src = ifaceInfo.ip;
        ipHdr->ip_dst = origIp->ip_src;
        ipHdr->ip_sum = 0;
        ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));
        
        icmpHdr->icmp_type = 11;
        icmpHdr->icmp_code = 0;
        icmpHdr->unused = 0;
        icmpHdr->next_mtu = 0;
        
        size_t dataToCopy = std::min(sizeof(icmpHdr->data),
            originalPacket.size() - sizeof(sr_ethernet_hdr_t));
        std::memcpy(icmpHdr->data, origIp, dataToCopy);
        
        icmpHdr->icmp_sum = 0;
        icmpHdr->icmp_sum = cksum(icmpHdr, sizeof(sr_icmp_t3_hdr_t));
        
        packetSender->sendPacket(icmpPacket, iface);
    } catch (const std::exception& e) {
        spdlog::error("Error in sendICMPT11Unreachable: {}", e.what());
    }
}