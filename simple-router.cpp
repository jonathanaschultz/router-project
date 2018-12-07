/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  const uint16_t ether_type = ethertype(packet.data()); //Get the packet type ID, make sure to convert endianness
  std::string p_addr = macToString(packet);
  std::string i_addr = macToString(iface -> addr);
  if ((p_addr != "ff:ff:ff:ff:ff:ff") && (p_addr != "FF:FF:FF:FF:FF:FF") && (p_addr != i_addr)) //Packet's HW address doesn't match interface or broadcast
  {
    std::cerr << "Destination HW address doesn't match interface/broadcast, ignoring" << std::endl;
    return;
  }
  else if (ether_type == ethertype_ip) //IPv4 packet, 0x8000 in hex
  {
    std::cerr << "Handling IPv4 packet" << std::endl;
    if (packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr)) //Too small
    {
      std::cerr << "Invalid packet size, too small for IPv4 and ethernet headers, ignoring" << std::endl;
      return;
    }
    ip_hdr *ip_head = const_cast<ip_hdr *>(reinterpret_cast<const ip_hdr *>(packet.data() + sizeof(ethernet_hdr))); //Get the IP header by getting the memory starting past the ethernet header
    if (ip_head -> ip_len < sizeof(ip_hdr)) //IP header specifically too small
    {
      std::cerr << "Invalid packet size, too small for IPv4 header, ignoring" << std::endl;
    }
    uint16_t cksum_old = ip_head -> ip_sum; //Old checksum
    ip_head -> ip_sum = 0; //Reset checksum
    if (cksum_old != cksum(ip_head, sizeof(ip_hdr))) //If checksum invalid, drop the packet
    {
      std::cerr << "Invalid packet checksum, ignoring" << std::endl;
      return;
    }
    for (auto inface = m_ifaces.begin(); inface != m_ifaces.end(); ++inface) //Make sure packet isn't destined for the router
    {
      if (inface -> ip == ip_head -> ip_dst) //If packet destined for router
      {
        std::cerr << "Packet destined for the router, ignoring" << std::endl;
        return;
      }
    }
    ip_head -> ip_ttl -= 1; //Decrement TTL
    if (ip_head -> ip_ttl <= 0) //If we have an invalid TTL, drop that packet like its hot
    {
      std::cerr << "Packet TTL limit exceeded, ignoring" << std::endl;
      return;
    }
    ip_head -> ip_sum = 0; //Reset checksum
    ip_head -> ip_sum = cksum(ip_head, sizeof(ip_hdr)); //Recalculate the checksum due to TTL change
    std::cerr << "Forwarding IPv4 packet" << std::endl;
    //Forwarding of packet starts here
    RoutingTableEntry rt_entry = m_routingTable.lookup(ip_head -> ip_dst); //Find next hop address via longest-prefix
    const Interface *ip_interface = findIfaceByName(rt_entry.ifName);
    auto arp_entry = m_arp.lookup(rt_entry.gw); //Check ARP cache, return the entry if one exists
    if (arp_entry == nullptr || arp_entry == NULL) //Not in the ARP cache, generate/send an ARP request
    {
      m_arp.queueRequest(rt_entry.gw, packet, ip_interface -> name);
      Buffer buf(sizeof(ethernet_hdr) + sizeof(arp_hdr)); //Buffer for ARP request
      ethernet_hdr *eth_req_head = reinterpret_cast<ethernet_hdr *>(buf.data());
      arp_hdr *arp_req_head = reinterpret_cast<arp_hdr *>(buf.data() + sizeof(ethernet_hdr));
      //Fill in the details for the ethernet header
      memcpy(eth_req_head -> ether_shost, ip_interface -> addr.data(), ETHER_ADDR_LEN);
      memcpy(eth_req_head -> ether_dhost, BroadcastEtherAddr, ETHER_ADDR_LEN);
      eth_req_head -> ether_type = htons(ethertype_arp);

      //Fill in the details for the ARP header
      arp_req_head -> arp_hrd = htons(arp_hrd_ethernet);
      arp_req_head -> arp_pro = htons(ethertype_ip);
      arp_req_head -> arp_hln = ETHER_ADDR_LEN;
      arp_req_head -> arp_pln = 4;
      arp_req_head -> arp_op = htons(arp_op_request);
      memcpy(arp_req_head -> arp_sha, ip_interface -> addr.data(), ETHER_ADDR_LEN);
      arp_req_head -> arp_sip = ip_interface -> ip;
      memcpy(arp_req_head -> arp_tha, BroadcastEtherAddr, ETHER_ADDR_LEN);
      arp_req_head -> arp_tip = rt_entry.gw;
      sendPacket(buf, ip_interface->name);
    }
    else //Already in the ARP cache, so we need to just grab the MAC and forward it onward
    {
      ethernet_hdr *ip_eth_head = const_cast<ethernet_hdr *>(reinterpret_cast<const ethernet_hdr *>(packet.data())); //Copy the existing packet data
      ip_eth_head -> ether_type = htons(ethertype_ip);
      memcpy(ip_eth_head -> ether_shost, ip_eth_head -> ether_dhost, ETHER_ADDR_LEN);
      memcpy(ip_eth_head -> ether_dhost, arp_entry -> mac.data(), ETHER_ADDR_LEN);
      sendPacket(packet, ip_interface -> name);
    }
  }
  else if (ether_type == ethertype_arp) //ARP packet, 0x8006 in hex
  {
    std::cerr << "Handling ARP packet" << std::endl;
    if (packet.size() < sizeof(ethernet_hdr) + sizeof(arp_hdr)) //Packet size is smaller than required, ignore
    {
      std::cerr << "Invalid packet size, too small for ARP, ignoring" << std::endl;
      return;
    }
    arp_hdr *arp_head = const_cast<arp_hdr *>(reinterpret_cast<const arp_hdr *>((packet.data() + sizeof(ethernet_hdr)))); //Get the ARP header by getting the memory starting past the ethernet header
    uint16_t op_type = ntohs(arp_head -> arp_op);
    if (op_type == arp_op_request) //ARP request, 0x0001 in hex
    {
      std::cerr << "Handling ARP request" << std::endl;
      if (arp_head -> arp_tip != iface -> ip) //ARP IP not equal to interface IP, drop it
      {
        std::cerr << "Invalid packet, ARP IP and interface IP not equal, ignoring" << std::endl;
        return;
      }
      Buffer buf(sizeof(ethernet_hdr) + sizeof(arp_hdr)); //Buffer for reply packet
      ethernet_hdr * reply_eth_head = reinterpret_cast<ethernet_hdr *>(buf.data());; //Reserve memory for ethernet header
      arp_hdr * reply_arp_head = reinterpret_cast<arp_hdr *>(buf.data()+ sizeof(ethernet_hdr)); //Reserve memory after ethernet header for ARP header
      //Construct ethernet header
      memcpy(reply_eth_head -> ether_shost, iface -> addr.data(), ETHER_ADDR_LEN); //Copy interface to be source
      memcpy(reply_eth_head -> ether_dhost, &(arp_head -> arp_sha), ETHER_ADDR_LEN); //Copy ARP frame for dest
      reply_eth_head -> ether_type = htons(ethertype_arp);
      //Construct ARP header, mostly copy from existing, swap destination and sources
      reply_arp_head -> arp_hrd = htons(ETHER_ADDR_LEN);
      reply_arp_head -> arp_pro = htons(ethertype_ip);
      reply_arp_head -> arp_hln = ETHER_ADDR_LEN;
      reply_arp_head -> arp_pln = 4;
      reply_arp_head -> arp_op = htons(arp_op_reply); //Reply opcode, switch endianness of bytes
      reply_arp_head -> arp_sip = iface -> ip; //Switch source and dest
      reply_arp_head -> arp_tip = arp_head -> arp_sip; //Switch source and dest
      memcpy(reply_arp_head -> arp_tha, &(arp_head -> arp_sha), ETHER_ADDR_LEN); //Switch source and dest
      memcpy(reply_arp_head -> arp_sha, iface -> addr.data(), ETHER_ADDR_LEN); //Switch source and dest
      std::cerr << "Created ARP reply in response of request" << std::endl;
      sendPacket(buf, iface->name); //Send the created reply packet
    }
    else if (op_type == arp_op_reply) //ARP reply, 0x0002 in hex
    {
      std::cerr << "Handling ARP reply" << std::endl;
      Buffer mBuf(ETHER_ADDR_LEN); //Buffer for MAC/IP combo to insert into the ARP cache
      uint8_t * mac_ptr = reinterpret_cast<uint8_t *>(mBuf.data()); //Pointer to the buffer
      memcpy(mac_ptr, arp_head -> arp_sha, ETHER_ADDR_LEN);
      auto arpReqEntry = m_arp.insertArpEntry(mBuf, (uint32_t) (arp_head -> arp_sip));
      if (arpReqEntry != nullptr) // && !arpReqEntry->packets.empty()) //All good to forward
      {
        for (auto p = arpReqEntry->packets.begin(); p != arpReqEntry->packets.end(); ++p)
        { //Forward individual packets from ARP reply
          std::cerr << "Forwarding packet in ARP reply" << std::endl;
          std::string iname = p -> iface;
          Buffer pend = p -> packet; //Buffer to store headers
          ethernet_hdr * pend_eth_head = reinterpret_cast<ethernet_hdr *>(pend.data());
          memcpy(pend_eth_head -> ether_dhost, mac_ptr, ETHER_ADDR_LEN);
          memcpy(pend_eth_head -> ether_shost, findIfaceByName(iname), ETHER_ADDR_LEN);
          ip_hdr * pend_ip_head = reinterpret_cast<ip_hdr *>(pend.data() + sizeof(ethernet_hdr));
          pend_ip_head -> ip_ttl -= 1;
          pend_ip_head -> ip_sum = 0;
          pend_ip_head -> ip_sum = cksum(pend_ip_head, ntohs(pend_ip_head -> ip_len));
          sendPacket(pend, iname);
        }
        m_arp.removeRequest(arpReqEntry); //We've finished it, so remove it
      }
      else
      {
        std::cerr << "Error in queueing packet, not queued, therefore ignoring" << std::endl;
        return;
      }
    }
    else //Neither ARP request or reply, ignore
    {
      std::cerr << "ARP opcode is neither request or reply, ignoring" << std::endl;
      return;
    }
  }
  else //Neither an IP or ARP packet, ignore
  {
    std::cerr << "Packet type is neither IPv4 or ARP, ignoring" << std::endl;
    return;
  }

}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
