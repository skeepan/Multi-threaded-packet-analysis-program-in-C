#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include "dispatch.h"

void terminate_pcap();
void sniff(char *interface, int verbose);

#endif
