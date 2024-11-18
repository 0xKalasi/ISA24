#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pcap/pcap.h>

#include <netinet/ip.h>  // struct ip
#include <netinet/tcp.h> // struct tcphdr
/* #include <netinet/if_ether.h> // for macOS */
#include <netinet/ether.h> // struct ether_header
#include <arpa/inet.h>     // ntohs

#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>

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

// NETFLOW v5 HEADER FORMAT
// variable type based on how many bytes header field needs
// https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006108 [16.11.2024]
// sum: 24 bytes
typedef struct
{
    uint16_t version;       // version 5
    uint16_t count;         // number of flows exported in this packet (1-30)
    uint32_t SysUptime;     // current time - boot time in miliseconds
    uint32_t unix_secs;     // current time in seconds since 0000 UTC 1970
    uint32_t unix_nsecs;    // current time in nanoseconds since 0000 UTC 1970
    uint32_t flow_sequence; // sequenceCount
    uint8_t engine_type;
    uint8_t engine_id;
    uint16_t sampling_interval;

} NetFlow_v5_header_t;

// NETFLOW v5 FLOW RECORD FORMAT
// sum: 48 bytes
// https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006186 [16.11.2024]
typedef struct
{
    uint32_t srcaddr; // source IP addr
    uint32_t dstaddr; // destination IP addr
    uint32_t nexthop;
    uint16_t input;
    uint16_t output;
    uint32_t dPkts;   // flow packet count
    uint32_t dOctets; // flow byte count
    uint32_t First;   // first packet time - boot time (in miliseconds)
    uint32_t Last;    // last packet time - boot time (in miliseconds)
    uint16_t srcport; // TCP source port
    uint16_t dstport; // TCP destination port
    uint8_t pad1;
    uint8_t tcp_flags;
    uint8_t prot; // TCP = 6
    uint8_t tos;
    uint16_t src_as;
    uint16_t dst_as;
    uint8_t src_mask; // 32
    uint8_t dst_mask; // 32
    uint16_t pad2;
} NetFlow_v5_record_t;

// GLOBAL VARIABLES
// use extern <type> <variableName>; to use in other .c files
// https://stackoverflow.com/questions/6792930/how-do-i-share-a-global-variable-between-c-files
config_t config;

flow_t flowsToExport[30];
int flowsToExportLength = 0;

flow_t *flows = NULL;
int flowsLength = 0;

int socketDescriptor;
struct sockaddr_in collector;

struct timeval bootTime;

int sequenceCount = 0;
int packetCount = 0;

// END GLOBAL VARIABLES

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

/* // THIS FUNCTION IS INSPIRED FROM SOFTFLOWD SOURCE CODE (softflowd/softflowd.c)
// TODO ADD LICENSE AND AUTHOR
uint32_t getSysUptime()
{
    // SysUptime = currentTime - bootTime (in miliseconds)
    struct timeval currentTime;
    gettimeofday(&currentTime, NULL);

    struct timeval result;

    result.tv_sec = currentTime.tv_sec - bootTime.tv_sec;
    result.tv_usec = currentTime.tv_sec - bootTime.tv_usec;

    if (result.tv_usec < 0)
    {
        result.tv_usec += 1000000L;
        result.tv_sec--;
    }

    return ((uint32_t)result.tv_sec * 1000 + (uint32_t)result.tv_usec / 1000);
} */

// THIS FUNCTION IS INSPIRED FROM SOFTFLOWD SOURCE CODE (softflowd/softflowd.c - timeval_sub_ms() line 686 [16.11.2024])
// https://github.com/irino/softflowd/blob/master/softflowd.c
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

/* void exportFlows()
{
    sequenceCount += flowsToExportLength;

    printf("sequenceCount = %d\n", sequenceCount);

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
} */

void exportFlows()
{
    printf("sequenceCount = %d\n", sequenceCount);

    uint8_t netFlowPacket[1470]; // 24 + (48 x 30) =  1 464
    int byteOffset = 0;

    // first we create header for packet
    NetFlow_v5_header_t header;
    memset(&header, 0, sizeof(NetFlow_v5_header_t)); // set every field of header to 0, we want to assign only some fields

    // set fields that we can set
    header.version = htons(5);
    header.count = htons(flowsToExportLength);

    // SysUptime = currentTime - bootTime (in miliseconds)
    struct timeval currentTime;
    gettimeofday(&currentTime, NULL);

    header.SysUptime = htonl(timeDiff(&currentTime, &bootTime));

    header.unix_secs = htonl((uint32_t)currentTime.tv_sec);
    header.unix_nsecs = htonl((uint32_t)currentTime.tv_usec * 1000);

    header.flow_sequence = htonl(sequenceCount);

    // copy header to packet, header is 24 bytes
    memcpy(netFlowPacket + byteOffset, &header, 24);
    byteOffset = 24;

    // after assigning flow_sequence, bcs we need to start flow_sequence from 0 with the first packet
    sequenceCount += flowsToExportLength;

    for (int i = 0; i < flowsToExportLength; i++)
    {
        flow_t *flow = &flowsToExport[i];

        NetFlow_v5_record_t flowRecord;
        memset(&flowRecord, 0, sizeof(NetFlow_v5_record_t)); // set every field of header to 0, we want to assign only some fields

        flowRecord.srcaddr = inet_addr(flow->srcIP);
        flowRecord.dstaddr = inet_addr(flow->destIP);
        flowRecord.dPkts = htonl(flow->packetCount);
        flowRecord.dOctets = htonl(flow->bytesCount);

        // first = first - bootTime (in miliseconds)
        flowRecord.First = htonl(timeDiff(&flow->first, &bootTime));

        // last = last - bootTime (in miliseconds)
        flowRecord.Last = htonl(timeDiff(&flow->last, &bootTime));

        flowRecord.srcport = htons(flow->srcPORT);
        flowRecord.dstport = htons(flow->destPORT);

        flowRecord.prot = 6; // TCP

        // flow record length is 48 bytes
        memcpy(netFlowPacket + byteOffset, &flowRecord, 48);
        byteOffset += 48;

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

    ssize_t bytesSent = sendto(socketDescriptor, netFlowPacket, byteOffset, 0, (struct sockaddr *)&collector, sizeof(collector));
    if (bytesSent == -1)
    {
        fprintf(stderr, "Error: sending NetFlow packet failed. Check if <host:port> is correct.\n");
        exit(1);
    }
    else
        printf("Succesfully sent %ld bytes to collector.\n", bytesSent);

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
    // moveToExport also manages if there is >= 30 flows to export
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

bool flowMatchPacket(flow_t *existingFlow, packet_t *packet)
{
    return (strcmp(existingFlow->srcIP, packet->srcIP) == 0 && strcmp(existingFlow->destIP, packet->destIP) == 0 && existingFlow->srcPORT == packet->srcPORT && existingFlow->destPORT == packet->destPORT);
}

void initSocket()
{
    struct addrinfo *resolved = NULL; // setting to NULL, because of warning
    struct addrinfo hints;

    // this has to be here, otherwise it always threw getaddrinfo error: ai_socktype not supported
    // https://stackoverflow.com/questions/5958817/getaddrinfo-error-ai-socktype-not-supported
    memset(&hints, 0, sizeof hints);

    hints.ai_family = AF_INET;      // IPv4
    hints.ai_socktype = SOCK_DGRAM; // UDP socket

    int ret = getaddrinfo(config.host, NULL, &hints, &resolved);
    if (ret != 0 || resolved->ai_addr == NULL)
    {
        freeaddrinfo(resolved);
        fprintf(stderr, "Error: getaddrinfo failed. %s\n", gai_strerror(ret));
        exit(1);
    }

    // setting collector IP and port
    collector = *(struct sockaddr_in *)resolved->ai_addr;
    collector.sin_port = htons(config.port);

    // setting socket
    socketDescriptor = socket(resolved->ai_family, resolved->ai_socktype, 0);
    if (socketDescriptor == -1)
    {
        freeaddrinfo(resolved);
        fprintf(stderr, "Error: socket creation failed\n");
        exit(1);
    }

    /* DEBUG */
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &((struct sockaddr_in *)resolved->ai_addr)->sin_addr, ip, INET_ADDRSTRLEN);
    printf("Resolved IP address: %s\n", ip);
    /* DEBUG */

    // free after we saved the IP resolved address to collector
    freeaddrinfo(resolved);
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

            // read IPv4 addresses from ip header
            inet_ntop(AF_INET, &(ipHeader->ip_src), currentPacket.srcIP, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ipHeader->ip_dst), currentPacket.destIP, INET_ADDRSTRLEN);

            // move to TCP header
            struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));

            // read ports from TCP header
            // byte length from IP header
            // timestamp from pcap header (frame)
            currentPacket.srcPORT = ntohs(tcpHeader->th_sport);
            currentPacket.destPORT = ntohs(tcpHeader->th_dport);
            currentPacket.bytes = ntohs(ipHeader->ip_len);
            currentPacket.timestamp = header->ts;

            /* printf("Packet %d: %s:%d -> %s:%d, Length %d bytes\n", *packetCount, srcIP, srcPort, dstIP, dstPort, byteLength); */

            checkTimeouts(currentPacket);

            bool flowFound = false;
            for (int i = 0; i < flowsLength; i++)
            {
                flow_t *existingFlow = &flows[i];

                // compare if packet belongs to flow
                if (flowMatchPacket(existingFlow, &currentPacket))
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

    initSocket();

    gettimeofday(&bootTime, NULL);
    printf("bootTime = %ld.%ld\n", bootTime.tv_sec, bootTime.tv_usec);

    /* LOOP */
    if (pcap_loop(pcapHandle, 0, packetHandler, NULL) == -1)
    {
        fprintf(stderr, "ERROR: processing packets: %s\n", pcap_geterr(pcapHandle));
        return 1;
    }

    printf("TCP packets count: %d\n", packetCount);
    /* LOOP */

    exportRemaining();

    printf("Exported %d flows\n", sequenceCount);

    closeHandle(pcapHandle);
    close(socketDescriptor);

    return 0;
}
