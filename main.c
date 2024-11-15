#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>

#include <netinet/ip.h>    // struct ip
#include <netinet/tcp.h>   // struct tcphdr
#include <netinet/ether.h> // struct ether_header
#include <arpa/inet.h>     // ntohs

#include "functions.h"
#include "pcap_functions.h"

typedef struct
{
    char srcIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    uint16_t srcPORT;
    uint16_t destPORT;
    int packetCount;
    int bytesCount;
} flow_t;

typedef struct
{
    flow_t *array;
    int *length;
    int *count;
} packetHandlerArgs_t;

void addFlow(flow_t packetInfo, flow_t *allFlowsArray, int *allFlowsArrayLength)
{
    // take first empty place in allFlowsArray
    flow_t *newFlow = &allFlowsArray[*allFlowsArrayLength];

    memcpy(newFlow, &packetInfo, sizeof(flow_t));

    // increment length, bcs we added newFlow
    (*allFlowsArrayLength)++;
}

void updateFlow(flow_t packetInfo, flow_t *existingFlow)
{
    existingFlow->bytesCount += packetInfo.bytesCount;
    existingFlow->packetCount++;
}

void exportFlows(flow_t *allFlowsArray, int *allFlowsArrayLength)
{
    printf("Exporting %d flows:\n", *allFlowsArrayLength);
    for (int i = 0; i < *allFlowsArrayLength; i++)
    {
        flow_t *flow = &allFlowsArray[i];

        printf("Flow %d: %s:%d -> %s:%d, packets: %u, bytes: %u\n",
               i + 1,
               flow->srcIP,
               flow->srcPORT,
               flow->destIP,
               flow->destPORT,
               flow->packetCount,
               flow->bytesCount);
    }

    *allFlowsArrayLength = 0;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr *header, const u_char *packet)
{
    packetHandlerArgs_t *args = (packetHandlerArgs_t *)userData;

    flow_t *flowsArray = args->array;
    int *flowsArrayLength = args->length;
    int *packetCount = args->count;

    printf("flowsArrayLength = %d\n", *flowsArrayLength);

    // ETHERNET HEADER
    struct ether_header *ethHeader = (struct ether_header *)packet;

    if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP)
    {
        // IP HEADER
        struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ether_header));

        // IN IP HEADER PROTOCOL FIELD (ip.proto)
        if (ipHeader->ip_p == IPPROTO_TCP)
        {
            (*packetCount)++;

            // variables to store IPv4 addresses
            char srcIP[INET_ADDRSTRLEN];
            char dstIP[INET_ADDRSTRLEN];

            // read IPv4 addresses from ip header and store them
            inet_ntop(AF_INET, &(ipHeader->ip_src), srcIP, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIP, INET_ADDRSTRLEN);

            // move to TCP header
            struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));

            // read ports from TCP header
            uint16_t srcPort = ntohs(tcpHeader->th_sport);
            uint16_t dstPort = ntohs(tcpHeader->th_dport);
            int byteLength = header->len;

            printf("Packet %d: %s:%d -> %s:%d, Length %d bytes\n", *packetCount, srcIP, srcPort, dstIP, dstPort, byteLength);

            // FLOWS
            flow_t packetInfo;
            strcpy(packetInfo.srcIP, srcIP);
            strcpy(packetInfo.destIP, dstIP);
            packetInfo.srcPORT = srcPort;
            packetInfo.destPORT = dstPort;
            packetInfo.packetCount = 1;
            packetInfo.bytesCount = byteLength;

            int flowFound = 0;

            for (int i = 0; i < *flowsArrayLength; i++)
            {
                flow_t *existingFlow = &flowsArray[i];

                // compare if packet belongs to flow
                if (strcmp(existingFlow->srcIP, packetInfo.srcIP) == 0 &&
                    strcmp(existingFlow->destIP, packetInfo.destIP) == 0 &&
                    existingFlow->srcPORT == packetInfo.srcPORT &&
                    existingFlow->destPORT == packetInfo.destPORT)
                {
                    updateFlow(packetInfo, existingFlow);
                    flowFound = 1;
                    break;
                }
            }

            if (!flowFound)
                addFlow(packetInfo, flowsArray, flowsArrayLength);

            if (*flowsArrayLength == 30)
                exportFlows(flowsArray, flowsArrayLength);
        }
    }
}

int main(int argc, char *argv[])
{
    config_t config;

    pcap_t *pcapHandle;

    flow_t flowsArray[30];
    int flowsArrayLength = 0;

    config = parseArgs(argc, argv);

    pcapHandle = createHandle(config.pcapFilePath);

    /* LOOP */
    int packetCount = 0;

    packetHandlerArgs_t args;
    args.array = flowsArray;
    args.length = &flowsArrayLength;
    args.count = &packetCount;

    if (pcap_loop(pcapHandle, 0, packetHandler, (u_char *)&args) == -1)
    {
        fprintf(stderr, "ERROR: processing packets: %s\n", pcap_geterr(pcapHandle));
        return 1;
    }

    printf("TCP packets count: %d\n", packetCount);
    /* LOOP */

    exportFlows(flowsArray, &flowsArrayLength);

    closeHandle(pcapHandle);

    return 0;
}
