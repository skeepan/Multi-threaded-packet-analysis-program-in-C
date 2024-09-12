#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>

#include "dispatch.h"

pcap_t *pcap_handle;

// Dispatch packet for processing
void packet_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    dispatch(pkthdr->len, packet);
}

// This function terminates all libpcap functions and frees memory.
void terminate_pcap() {
  pcap_breakloop(pcap_handle);
  pcap_close(pcap_handle);
}

// Application main sniffing loop
void sniff(char *interface, int verbose) {
  signal(SIGINT, signalHandler);
  char errbuf[PCAP_ERRBUF_SIZE];

  // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
  // capturing session. check the man page of pcap_open_live()
  
  pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }
  
  init_threadq();
  
  pcap_loop(pcap_handle, -1, packet_handler, NULL);
}

