#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <arpa/inet.h>

#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>

#include "flow_functions.h"

extern flow_t flowsToExport[30];
extern int flowsToExportLength;

extern flow_t *flows;
extern int flowsLength;

extern struct timeval bootTime;
extern struct sockaddr_in collector;
extern int socketDescriptor;
extern int sequenceCount;
extern config_t config;

void exportFlows()
{
    /* printf("sequenceCount = %d\n", sequenceCount); */

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

        /* printf("Flow %d: %s:%d -> %s:%d, packets: %d, bytes: %d, first: %ld.%ld, last: %ld.%ld\n",
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
                flow->last.tv_usec); */
    }

    ssize_t bytesSent = sendto(socketDescriptor, netFlowPacket, byteOffset, 0, (struct sockaddr *)&collector, sizeof(collector));
    if (bytesSent == -1)
    {
        fprintf(stderr, "Error: sending NetFlow packet failed. Check if <host:port> is correct.\n");
        exit(1);
    }
    /* else
        printf("Succesfully sent %ld bytes to collector.\n", bytesSent); */

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
        /* printf("Exporting remaining %d flows:\n", flowsToExportLength); */
        exportFlows();
    }
    /* else
    printf("No remaining flows to export.\n"); */
}

void initCollector()
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

    // free after we saved the IP resolved address to collector
    freeaddrinfo(resolved);
}