#ifndef PCAP_FUNCTIONS_H

#include <stdio.h>
#include <stdlib.h>

#include <pcap/pcap.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

pcap_t *createHandle(const char *file);

void closeHandle(pcap_t *pcapHandle);

void packetHandler(u_char *userData, const struct pcap_pkthdr *header, const u_char *packet);

#endif