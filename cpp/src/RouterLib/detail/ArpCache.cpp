#include "ArpCache.h"

#include <thread>
#include <cstring>
#include <spdlog/spdlog.h>

#include "protocol.h"
#include "utils.h"

ArpCache::ArpCache(
    std::chrono::milliseconds entryTimeout, 
    std::chrono::milliseconds tickInterval, 
    std::chrono::milliseconds resendInterval,
    std::shared_ptr<IPacketSender> packetSender, 
    std::shared_ptr<IRoutingTable> routingTable)
: entryTimeout(entryTimeout)
, tickInterval(tickInterval)
, resendInterval(resendInterval)
, packetSender(std::move(packetSender))
, routingTable(std::move(routingTable)) {
    thread = std::make_unique<std::thread>(&ArpCache::loop, this);
}

ArpCache::~ArpCache() {
    shutdown = true;
    if (thread && thread->joinable()) {
        thread->join();
    }
}

void ArpCache::loop() {
    while (!shutdown) {
        tick();
        std::this_thread::sleep_for(tickInterval);
    }
}

void ArpCache::tick() {
    std::unique_lock lock(mutex);
    auto now = std::chrono::steady_clock::now();
    
    std::vector<uint32_t> eraseIps;
    for (auto& [ip, request] : pendingRequests) {
        auto timeSinceLastSent = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - request.lastSent);

        if (timeSinceLastSent >= resendInterval) {
            if (request.timesSent < 7) {
                // Send ARP request
                if (!request.packets.empty()) {
                    sendArpRequest(ip, request.packets[0].iFaceTo);
                }
                request.lastSent = now;
                request.timesSent++;
            } else {
                // Failed after 7 attempts - send ICMP host unreachable
                eraseIps.push_back(ip);
                for (const auto& pending : request.packets) {
                    sendICMPHostUnreachable(pending.packet, pending.iFaceFrom);
                }
            }
        }
    }
    
    for (uint32_t ip : eraseIps) {
        pendingRequests.erase(ip);
    }
    
    std::erase_if(entries, [this, now](const auto& entry) {
        return now - entry.second.timeAdded >= entryTimeout;
    });
}

void ArpCache::addEntry(uint32_t ip, const mac_addr& mac) {
    std::unique_lock lock(mutex);
    
    // Add entry to cache
    ArpEntry entry;
    entry.mac = mac;
    entry.timeAdded = std::chrono::steady_clock::now();
    entries[ip] = entry;
    
    auto it = pendingRequests.find(ip);
    if (it != pendingRequests.end()) {
        for (const auto& pending : it->second.packets) {
            if (pending.packet.size() >= sizeof(sr_ethernet_hdr_t)) {
                Packet outPacket = pending.packet;
                sr_ethernet_hdr_t* ethHdr = reinterpret_cast<sr_ethernet_hdr_t*>(outPacket.data());
                
                std::memcpy(ethHdr->ether_dhost, mac.data(), ETHER_ADDR_LEN);
                
                try {
                    auto iface = routingTable->getRoutingInterface(pending.iFaceTo);
                    std::memcpy(ethHdr->ether_shost, iface.mac.data(), ETHER_ADDR_LEN);
                } catch (...) {
                    spdlog::error("Failed to get interface info for {}", pending.iFaceTo);
                    continue;
                }
                
                packetSender->sendPacket(outPacket, pending.iFaceTo);
            }
        }
        
        pendingRequests.erase(it);
    }
}

std::optional<mac_addr> ArpCache::getEntry(uint32_t ip) {
    std::unique_lock lock(mutex);

    auto it = entries.find(ip);
    if (it != entries.end()) {
        return it->second.mac;
    }

    return std::nullopt;
}

void ArpCache::queuePacket(uint32_t ip, const Packet& packet, const std::string& iface) {
    std::unique_lock lock(mutex);

    if (packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        return;
    }

    PendingPacket pending;
    pending.packet = packet;
    pending.iFaceFrom = iface;
    
    const sr_ip_hdr_t* ip_hdr = reinterpret_cast<const sr_ip_hdr_t*>(
        packet.data() + sizeof(sr_ethernet_hdr_t));
    
    auto optEntry = routingTable->getRoutingEntry(ip_hdr->ip_dst);
    if (!optEntry.has_value()) {
        spdlog::error("No routing entry found for destination IP");
        return;
    }
    
    pending.iFaceTo = optEntry.value().iface;
    
    auto& request = pendingRequests[ip];
    request.packets.push_back(pending);
    
    if (request.timesSent == 0) {
        sendArpRequest(ip, pending.iFaceTo);
        request.lastSent = std::chrono::steady_clock::now() - resendInterval;
        request.timesSent++;
    }
}

void ArpCache::sendArpRequest(uint32_t targetIp, const std::string& iface) {
    try {
        auto ifaceInfo = routingTable->getRoutingInterface(iface);
        
        spdlog::info("Sending ARP request: iface={}, sip={}, tip={}",
                     iface, ntohl(ifaceInfo.ip), ntohl(targetIp));
        
        std::vector<uint8_t> arpPacket(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
        
        sr_ethernet_hdr_t* ethHdr = reinterpret_cast<sr_ethernet_hdr_t*>(arpPacket.data());
        sr_arp_hdr_t* arpHdr = reinterpret_cast<sr_arp_hdr_t*>(
            arpPacket.data() + sizeof(sr_ethernet_hdr_t));
        
        std::memset(ethHdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
        std::memcpy(ethHdr->ether_shost, ifaceInfo.mac.data(), ETHER_ADDR_LEN);
        ethHdr->ether_type = htons(ethertype_arp);
        
        arpHdr->ar_hrd = htons(arp_hrd_ethernet);
        arpHdr->ar_pro = htons(ethertype_ip);
        arpHdr->ar_hln = ETHER_ADDR_LEN;
        arpHdr->ar_pln = 4;
        arpHdr->ar_op = htons(arp_op_request);
        
        std::memcpy(arpHdr->ar_sha, ifaceInfo.mac.data(), ETHER_ADDR_LEN);
        arpHdr->ar_sip = ifaceInfo.ip;
        std::memset(arpHdr->ar_tha, 0x00, ETHER_ADDR_LEN);
        arpHdr->ar_tip = targetIp;
        
        packetSender->sendPacket(arpPacket, iface);
    } catch (const std::exception& e) {
        spdlog::error("Failed to send ARP request: {}", e.what());
    }
}

void ArpCache::sendICMPHostUnreachable(const Packet& originalPacket, const std::string& iface) {
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