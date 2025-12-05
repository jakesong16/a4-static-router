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
    if(routing_interface.ip != ip_hdr->ip_dst){
        forwardIPPacket(packet, iface);
    } else {
        if(ip_hdr->ip_tos == ip_protocol_tcp || ip_hdr->ip_tos == ip_protocol_udp){
            sendUnreachable(eth_hdr, ip_hdr, iface, 3, 3); //port unreachable
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
            "Received quited ARP reply on iface {}: from IP {} to IP {}",
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
        sendUnreachable(eth_hdr, ip_hdr, iface, 11, 0);
        return;
    }
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr));
    auto optEntry = routingTable->getRoutingEntry(ip_hdr->ip_dst); 
    if(!optEntry.has_value()){
        sendUnreachable(eth_hdr, ip_hdr, iface, 3, 0); //Dest net unreachable
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

void StaticRouter::createICMPHeaderTemplate(sr_ethernet_hdr *  eth_hdr, sr_ip_hdr * ip_hdr, std::vector<uint8_t> &icmp_packet, std::string &iface){
    
    
    sr_ip_hdr *  icmp_ip_hdr = reinterpret_cast<sr_ip_hdr*>(icmp_packet.data()+sizeof(sr_ethernet_hdr));
    // ICMP_ip_hdr.ip_tos 
    icmp_ip_hdr->ip_v  =  4;   
    icmp_ip_hdr->ip_hl = 5;
    icmp_ip_hdr->ip_tos = 0;
    icmp_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr) + sizeof(sr_icmp_hdr) + 4 + 8);
    icmp_ip_hdr->ip_id = 0;
    icmp_ip_hdr->ip_off = htons(IP_DF);
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


void StaticRouter::sendUnreachable(sr_ethernet_hdr *  eth_hdr, sr_ip_hdr * ip_hdr, std::string &iface, uint8_t type, uint8_t code){
    constexpr size_t icmp_payload_len =
        sizeof(sr_icmp_hdr) + 4 + sizeof(sr_ip_hdr) + 8;
    constexpr size_t ip_total_len = sizeof(sr_ip_hdr) + icmp_payload_len;
    std::vector<uint8_t> icmp_packet(sizeof(sr_ethernet_hdr)+ip_total_len, 0);

    createICMPHeaderTemplate(eth_hdr, ip_hdr, icmp_packet, iface);

    
    sr_icmp_hdr * icmp_hdr = reinterpret_cast<sr_icmp_hdr*>(icmp_packet.data()+sizeof(sr_ethernet_hdr)+sizeof(sr_ip_hdr));
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    

    uint8_t* icmp_payload = reinterpret_cast<uint8_t*>(icmp_hdr) + sizeof(sr_icmp_hdr) + 4;
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

    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_packet.data()+sizeof(sr_ethernet_hdr_t) +sizeof(sr_ip_hdr),
                               icmp_packet.size() - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr) - sizeof(sr_icmp_hdr));

    forwardIPPacket(icmp_packet, iface);
}

void StaticRouter::sendEchoReply(std::vector<uint8_t> &packet, std::string &iface){
    std::vector<uint8_t> icmp_packet(packet.size());
    sr_ethernet_hdr * eth_hdr = reinterpret_cast<sr_ethernet_hdr*>(packet.data());
    sr_ip_hdr * ip_hdr = reinterpret_cast<sr_ip_hdr*>(packet.data()+sizeof(sr_ethernet_hdr));
    createICMPHeaderTemplate(eth_hdr, ip_hdr, icmp_packet, iface);
    spdlog::info(
            "Send echo reply from iface {}: from IP {} to IP {}",
            iface,
            ntohl(ip_hdr->ip_src),
            ntohl(ip_hdr->ip_dst)
        );

    sr_icmp_hdr * icmp_hdr = reinterpret_cast<sr_icmp_hdr*>(icmp_packet.data()+sizeof(sr_ethernet_hdr)+sizeof(sr_ip_hdr));
    icmp_hdr->icmp_type = 0;
    icmp_hdr->icmp_code = 0;  

    uint8_t* icmp_payload = reinterpret_cast<uint8_t*>(icmp_hdr) + sizeof(sr_icmp_hdr) + 4;
    std::copy(
        packet.begin() +sizeof(sr_ethernet_hdr) + sizeof(sr_ip_hdr) + sizeof(sr_icmp_hdr),
        packet.end(),
        icmp_payload
    );

    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_packet.data()+sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr),
                               icmp_packet.size() - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr));

    forwardIPPacket(icmp_packet, iface);
}

