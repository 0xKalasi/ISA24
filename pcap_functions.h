#ifndef PCAP_FUNCTIONS_H

#include <stdio.h>
#include <stdlib.h>

#include <pcap/pcap.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

/* typedef struct
{
    flow_t *array;
    int *length;
    int *count;
} packetHandlerArgs_t; */

pcap_t *createHandle(const char *file);

void closeHandle(pcap_t *pcapHandle);

/* void loopFile(pcap_t *pcapHandle, flow_t *allFlowsArray, int *allFlowsArrayLength);

void packetHandler(u_char *userData, const struct pcap_pkthdr *header, const u_char *packet); */

#endif