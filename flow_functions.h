#ifndef FLOW_FUNCTIONS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/ip.h> //INET_ADDRSTRLEN

typedef struct
{
    char srcIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    uint16_t srcPORT;
    uint16_t destPORT;
    int packetCount;
    int bytesCount;
} flow_t;

// using flow_t for packetInfo
// set packetCount to 1, bytesCount to packet length
// before adding flow check allFlowsArrayLength if allFlowsArray is not already full ready for export
void addFlow(flow_t packetInfo, flow_t *allFlowsArray, int *allFlowsArrayLength);

// packetInfo must be already full of data
// set packetCount = NULL
// set bytesCount = header->len
void updateFlow(flow_t packetInfo, flow_t *existingFlow);

void exportFlows(flow_t *allFlowsArray, int *allFlowsArrayLength);

#endif