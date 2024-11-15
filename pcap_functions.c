#include <stdio.h>
#include <stdlib.h>

#include <pcap/pcap.h>

#include <netinet/ip.h>    // struct ip
#include <netinet/tcp.h>   // struct tcphdr
#include <netinet/ether.h> // struct ether_header
#include <arpa/inet.h>     // ntohs

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

    struct ether_header *ethHeader = (struct ether_header *)packet;

    if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP)
    {
        struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ether_header));

        if (ipHeader->ip_p == IPPROTO_TCP)
            (*packetCount)++;
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