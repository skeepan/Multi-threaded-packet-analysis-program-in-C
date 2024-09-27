#ifndef CAPTURE_H
#define CAPTURE_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include "thread_dispatch.h"

void terminate_pcap();
void capture(char *interface, int verbose);

#endif
