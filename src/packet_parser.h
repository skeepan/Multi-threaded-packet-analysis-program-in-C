#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include "packet_parser.h"
#include "queue.h"
#include "hashmap.h"

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>

typedef struct stat_parse {
  uint32_t source_ip;  // 32-bit unsigned integer representing source IP
  uint8_t SYN : 1;     // 1-bit flag for SYN
  uint8_t ARPrsp : 1;  // 1-bit flag for ARPrsp
  uint8_t GOOGLE : 1;  // 1-bit flag for GOOGLE
  uint8_t BBC : 1;     // 1-bit flag for BBC
} StatParse;

void printParseFlags(StatParse* parse);

StatParse* init_Parse(void);
void reset_Parse(StatParse* parse);

void parse_packet(const unsigned char *packet, StatParse *parse);

#endif
