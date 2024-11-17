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
    struct timeval first;
    struct timeval last;
} flow_t;

typedef struct
{
    char srcIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    uint16_t srcPORT;
    uint16_t destPORT;
    int bytes;
    struct timeval timestamp;
} packet_t;

// GLOBAL VARIABLES
// use extern <type> <variableName>; to use in other .c files
// https://stackoverflow.com/questions/6792930/how-do-i-share-a-global-variable-between-c-files
flow_t flowsToExport[30];
int flowsToExportLength = 0;

flow_t *flows = NULL;
int flowsLength = 0;

int exportedCount = 0;
int packetCount = 0;

config_t config;

void addFlow(packet_t packet)
{

    // reallocating flow_t * 30 everytime flowLength is 30 / 60 / 90 etc.
    if (flowsLength % 30 == 0)
    {
        flows = realloc(flows, (flowsLength + 30) * sizeof(flow_t));

        if (!flows)
        {
            fprintf(stderr, "Error: memory reallocation failed. Function addFlow.\n");
            exit(1);
        }
    }

    flows[flowsLength] = (flow_t){
        .srcPORT = packet.srcPORT,
        .destPORT = packet.destPORT,
        .bytesCount = packet.bytes,
        .packetCount = 1,
        .first = packet.timestamp,
        .last = packet.timestamp};

    strcpy(flows[flowsLength].srcIP, packet.srcIP);
    strcpy(flows[flowsLength].destIP, packet.destIP);

    // increment length, bcs we added new flow
    flowsLength++;
}

void updateFlow(packet_t packet, flow_t *existingFlow)
{
    existingFlow->bytesCount += packet.bytes;
    existingFlow->packetCount++;
    existingFlow->last = packet.timestamp;
}

void exportFlows()
{
    printf("Exporting %d flows:\n", flowsToExportLength);
    for (int i = 0; i < flowsToExportLength; i++)
    {
        flow_t *flow = &flowsToExport[i];

        printf("Flow %d: %s:%d -> %s:%d, packets: %d, bytes: %d, first: %ld.%ld, last: %ld.%ld\n",
               i + 1,
               flow->srcIP,
               flow->srcPORT,
               flow->destIP,
               flow->destPORT,
               flow->packetCount,
               flow->bytesCount,
               flow->first.tv_sec,
               flow->first.tv_usec,
               flow->last.tv_sec,
               flow->last.tv_usec);
    }

    flowsToExportLength = 0;
}

// moves flow at param index to flowsToExport array
// also checks if there is already 30 flows to export and if yes, exports them
void moveToExport(int index)
{
    if (flowsToExportLength == 30)
        exportFlows();

    flowsToExport[flowsToExportLength] = flows[index];
    flowsToExportLength++;

    // flowsLength - 1, bcs if not, seg. fault would occur bcs we would have tried to go to not ours memory
    for (int i = index; i < flowsLength - 1; i++)
        flows[i] = flows[i + 1];

    flowsLength--;
}

void exportRemaining()
{
    // moveToExport also manages to exportFlows if there is >= 30 flows to export
    int i = 0;
    while (i < flowsLength)
        moveToExport(i);

    if (flowsToExportLength > 0)
    {
        printf("Exporting remaining %d flows:\n", flowsToExportLength);
        exportFlows();
    }
    else
        printf("No remaining flows to export.\n");
}

// check active and inactive timeout
// move flow to export if atleast one of the timeouts got triggered
void checkTimeouts(packet_t packet)
{
    for (int i = 0; i < flowsLength; i++)
    {
        flow_t *flow = &flows[i];

        // active timeout
        // (current - first) >= activeTimeout
        uint32_t active = packet.timestamp.tv_sec - flow->first.tv_sec;

        // inactive timeout
        // (current - last) >= inactiveTimeout
        uint32_t inactive = packet.timestamp.tv_sec - flow->last.tv_sec;

        if (active >= (uint32_t)config.activeTimeout || inactive >= (uint32_t)config.inactiveTimeout)
            moveToExport(i);
    }
}

// THIS FUNCTION IS INSPIRED FROM SOFTFLOWD SOURCE CODE (softflowd/softflowd.c)
// TODO ADD LICENSE AND AUTHOR
uint32_t timeDiff(const struct timeval *one, const struct timeval *two)
{
    struct timeval result;
    result.tv_sec = one->tv_sec - two->tv_sec;
    result.tv_usec = one->tv_usec - two->tv_usec;

    if (result.tv_usec < 0)
    {
        result.tv_usec += 1000000L;
        result.tv_sec--;
    }

    return ((uint32_t)result.tv_sec * 1000 + (uint32_t)result.tv_usec / 1000);
}

void packetHandler(u_char *userData, const struct pcap_pkthdr *header, const u_char *packet)
{
    // warning psst
    if (userData)
    {
    }

    // ETHERNET HEADER
    struct ether_header *ethHeader = (struct ether_header *)packet;

    if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP)
    {
        // IP HEADER
        struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ether_header));

        // IN IP HEADER PROTOCOL FIELD (ip.proto)
        if (ipHeader->ip_p == IPPROTO_TCP)
        {
            packetCount++;

            packet_t currentPacket;

            // read IPv4 addresses from ip header and store them
            inet_ntop(AF_INET, &(ipHeader->ip_src), currentPacket.srcIP, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ipHeader->ip_dst), currentPacket.destIP, INET_ADDRSTRLEN);

            // move to TCP header
            struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));

            // read ports from TCP header and byte length from pcap header
            currentPacket.srcPORT = ntohs(tcpHeader->th_sport);
            currentPacket.destPORT = ntohs(tcpHeader->th_dport);
            currentPacket.bytes = header->len;
            currentPacket.timestamp = header->ts;

            /* printf("Packet %d: %s:%d -> %s:%d, Length %d bytes\n", *packetCount, srcIP, srcPort, dstIP, dstPort, byteLength); */

            checkTimeouts(currentPacket);

            int flowFound = 0;
            for (int i = 0; i < flowsLength; i++)
            {
                flow_t *existingFlow = &flows[i];

                // compare if packet belongs to flow
                if (strcmp(existingFlow->srcIP, currentPacket.srcIP) == 0 &&
                    strcmp(existingFlow->destIP, currentPacket.destIP) == 0 &&
                    existingFlow->srcPORT == currentPacket.srcPORT &&
                    existingFlow->destPORT == currentPacket.destPORT)
                {
                    updateFlow(currentPacket, existingFlow);
                    flowFound = 1;
                    break;
                }
            }

            if (!flowFound)
                addFlow(currentPacket);
        }
    }
}

int main(int argc, char *argv[])
{
    pcap_t *pcapHandle;

    config = parseArgs(argc, argv);

    pcapHandle = createHandle(config.pcapFilePath);

    /* LOOP */
    if (pcap_loop(pcapHandle, 0, packetHandler, NULL) == -1)
    {
        fprintf(stderr, "ERROR: processing packets: %s\n", pcap_geterr(pcapHandle));
        return 1;
    }

    printf("TCP packets count: %d\n", packetCount);
    /* LOOP */

    exportRemaining();

    closeHandle(pcapHandle);

    return 0;
}
