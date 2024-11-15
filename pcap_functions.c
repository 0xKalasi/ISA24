#include <stdio.h>
#include <stdlib.h>

#include <pcap/pcap.h>

#include <netinet/ip.h>    // struct ip
#include <netinet/tcp.h>   // struct tcphdr
#include <netinet/ether.h> // struct ether_header
#include <arpa/inet.h>     // ntohs, inet_ntoa

pcap_t *createHandle(const char *file)
{
    pcap_t *pcapHandle;
    pcapHandle = pcap_open_offline(file, NULL);

    if (!pcapHandle)
    {
        fprintf(stderr, "ERROR: could not open PCAP file.\n");
        exit(1);
    }

    return pcapHandle;
}

void closeHandle(pcap_t *pcapHandle)
{
    pcap_close(pcapHandle);
}

void packetHandler(u_char *userData, const struct pcap_pkthdr *header, const u_char *packet)
{
    int *packetCount = (int *)userData;

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
        }
    }
}

void loopFile(pcap_t *pcapHandle)
{
    int packetCount = 0;

    if (pcap_loop(pcapHandle, 0, packetHandler, (u_char *)&packetCount) == -1)
    {
        fprintf(stderr, "ERROR: processing packets: %s\n", pcap_geterr(pcapHandle));
        return;
    }

    printf("TCP packets count: %d\n", packetCount);
}