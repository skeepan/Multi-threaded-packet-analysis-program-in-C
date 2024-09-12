#include "analysis.h"

#include <net/ethernet.h>     // Ether header for Intellisense
#include <netinet/if_ether.h> // Ether/ARP header
#include <netinet/ip.h>       // IP header
#include <netinet/tcp.h>      // TCP header
#include <arpa/inet.h>        // making IP to readable
#include <string.h>           // strcmp / strstr for URL
#include <pcap.h>             // for pcap_pkthdr

StatParse* init_Parse(void) {                                       //This function initialises a StatParse struct which keeps track of which attacks have been detected. 
  StatParse* parse = (StatParse *)malloc(sizeof(StatParse));
  parse->SYN = 0;
  parse->ARPrsp = 0;
  parse->GOOGLE = 0;
  parse->BBC = 0;
  parse->source_ip = 0;
  return parse;
}

void reset_Parse(StatParse* parse) {                                //This function resets all flags within the struct for a new packet.
  parse->SYN = 0;
  parse->ARPrsp = 0;
  parse->GOOGLE = 0;
  parse->BBC = 0;
  parse->source_ip = 0;
}

void analyse(const unsigned char *packet, StatParse *parse) { 

  reset_Parse(parse);
  struct ether_header *eth_header = (struct ether_header *) packet;   //Makes the ether header readable by typecasting the data to ether_header struct
  uint16_t packet_ether_type = ntohs(eth_header->ether_type);         //16 bit field requires ntohs

  if (packet_ether_type == ETH_P_IP) {                                //Check if the next protocol is IP

    //IP header and length
    struct iphdr *ip_header = (struct iphdr *) (packet+ETH_HLEN);
    int ip_len = 4*(ip_header->ihl);

    if (ip_header->protocol == 0x6) {                                 //Check if the next protocol is TCP
      
      //TCP header and length
      struct tcphdr *tcp_header = (struct tcphdr *) (packet+ETH_HLEN+ip_len);
      int tcp_len = 4*(tcp_header->th_off);
      
      const unsigned char *payload = (const unsigned char *) (packet+ETH_HLEN+ip_len+tcp_len);

      uint8_t flags = tcp_header->th_flags;
      uint16_t dest_port = ntohs(tcp_header->th_dport);

      if ((flags & TH_SYN) && !(flags & TH_ACK)) {                      //SYN Attack check: check if the SYN flag is on and ACK is NOT on
        uint32_t source_ip = (uint32_t) ntohl(ip_header->saddr);        //32 bit field requires ntohl
        parse->SYN |= 1;
        parse->source_ip = source_ip;
      }
    
      if (dest_port == 0x50 || dest_port == 0x1F90) {                   //Blacklisted URL check: check if sending to Port 80 or 8080 (http request)
        char *hostSubstring = strstr((const char *) payload, "Host:");

        if (hostSubstring != NULL) {
          if (strstr(hostSubstring, "www.google.co.uk") != NULL) {
            parse->GOOGLE |= 1;
          }
          else if (strstr(hostSubstring, "www.bbc.co.uk") != NULL)  {
            parse->BBC |= 1;
          }
        }
        if (parse->BBC || parse->GOOGLE) {
          const char *website = (parse->GOOGLE) ? "(google)" : "(bbc)";
          char dest_ip_str[INET_ADDRSTRLEN];
          char source_ip_str[INET_ADDRSTRLEN];
          inet_ntop(AF_INET, &(ip_header->daddr), dest_ip_str, sizeof(dest_ip_str));
          inet_ntop(AF_INET, &(ip_header->saddr), source_ip_str, sizeof(source_ip_str));
          printf("\n==============================\nBlacklisted URL violation detected\nSource IP address: %s \nDestination IP address: %s %s \n==============================\n",source_ip_str, dest_ip_str, website);
        }
      }
    }
  }

  else if (packet_ether_type == ETH_P_ARP) {                         //ARP Poison check: Check if ARP code is a reply. 
    struct ether_arp *arp_header = (struct ether_arp *) (packet+ETH_HLEN);
    if (ntohs(arp_header->ea_hdr.ar_op) == 0x0002) {                
      parse->ARPrsp |= 1;
    }
  }

}
