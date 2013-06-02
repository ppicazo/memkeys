#include <iostream>
#include <iomanip>
#include <string>
#include <pcrecpp.h>

#include "net/net.h"

extern "C" {
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
}

static inline std::string ipv4addressToString(const void * src) {
  char ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, src, ip, INET_ADDRSTRLEN);
  return std::string(ip);
}

namespace mckeys {

using namespace std;

// Like getInstance. Used for creating commands from packets.
MemcacheCommand MemcacheCommand::create(const Packet& pkt,
                                        const bpf_u_int32 captureAddress)
{
  const Packet::Header* pkthdr = &pkt.getHeader();
  const Packet::Data* packet = pkt.getData();

  bool possible_request = false;
  u_char *data;
  uint32_t dataLength = 0;

  string sourceAddress = "";

  // must be an IP packet
  // TODO add support for dumping localhost
  const struct ether_header* ethernetHeader = (struct ether_header*)packet;
  ssize_t ethernetHeaderSize = sizeof(struct ether_header); //14 bytes
  auto etype = ntohs(ethernetHeader->ether_type);
  if (etype != ETHERTYPE_IP) {
    return MemcacheCommand();
  }

  // must be TCP - TODO add support for UDP
  const struct ip* ipHeader = (struct ip*)(packet + ethernetHeaderSize);
  ssize_t ipHeaderSize = ipHeader->ip_hl * 4;
  auto itype = ipHeader->ip_p;
  if (itype != IPPROTO_TCP) {
    return MemcacheCommand();
  }
  sourceAddress = ipv4addressToString(&(ipHeader->ip_src));

  // The packet was destined for our capture address, this is a request
  // This bit of optimization lets us ignore a reasonably large percentage of
  // traffic
  if (ipHeader->ip_dst.s_addr == captureAddress) {
    possible_request = true;
  }
  // FIXME will remove once we add back the direction parsing
  (void)possible_request;

  const struct tcphdr* tcpHeader = (struct tcphdr*)(packet + ethernetHeaderSize 
                                                    + ipHeaderSize);
  ssize_t tcpHeaderSize = tcpHeader->doff * 4;
  (void)tcpHeader;
  data = (u_char*)(packet + ethernetHeaderSize + ipHeaderSize + tcpHeaderSize);
  dataLength = pkthdr->len - (ethernetHeaderSize + ipHeaderSize + tcpHeaderSize);
  if (dataLength > pkthdr->caplen) {
    dataLength = pkthdr->caplen;
  }

  // TODO revert to detecting request/response and doing the right thing
  if (dataLength <= 0) {
    return MemcacheCommand();
  }
  return MemcacheCommand::makeResponse(data, dataLength, sourceAddress);
}

// protected default constructor
MemcacheCommand::MemcacheCommand()
  : cmdType_(MC_UNKNOWN),
    sourceAddress_(),
    commandName_()
{}

// protected constructor
MemcacheCommand::MemcacheCommand(const memcache_command_t cmdType,
                                 const string sourceAddress,
                                 const string commandName)
    : cmdType_(cmdType),
      sourceAddress_(sourceAddress),
      commandName_(commandName)
{}

MemcacheCommand::MemcacheCommand(const memcache_command_t cmdType,
                                 const string sourceAddress,
                                 const string commandName,
                                 const string objectKey,
                                 uint32_t objectSize)
    : cmdType_(cmdType),
      sourceAddress_(sourceAddress),
      commandName_(commandName)
{
  pushObject(objectKey, objectSize);
}

void MemcacheCommand::pushObject(const std::string objectKey, uint32_t objectSize)
{
  objectKeyList_.push_back(objectKey);
  objectSizeList_.push_back(objectSize);
}

// static protected
MemcacheCommand MemcacheCommand::makeRequest(u_char*, int, string)
{
  // don't care about requests right now
  return MemcacheCommand();
}

// static protected
MemcacheCommand MemcacheCommand::makeResponse(u_char *data, int length,
                                              string sourceAddress)
{
  static pcrecpp::RE re("(VALUE (\\S+) \\d+ (\\d+))",
                        pcrecpp::RE_Options(PCRE_MULTILINE));
  static int minimum_length = 11; // 'VALUE a 0 1'

  string whole;
  string key;
  int size = -1;

  MemcacheCommand mc(MC_RESPONSE, sourceAddress, "");
  int offset = 0;
  while (length - offset >= minimum_length) {
    //Logger::getLogger("command")->debug(CONTEXT, "%.*s", length, data + offset);
    if (!re.PartialMatch(data + offset, &whole, &key, &size)) {
      break;
    }
    //Logger::getLogger("command")->debug(whole);
    //Logger::getLogger("command")->debug(key);
    if (size >= 0) {
      mc.pushObject(key, size);
      offset += whole.length() + 2 + size + 2; // 2 for '\r\n', 2 for '\r\n'
    } else {
      break;
    }
  }

  if (mc.getObjectNumber() > 0) {
    return mc;
  } else {
    return MemcacheCommand();
  }
}

} // end namespace
