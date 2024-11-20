/*
    [ISA project] - PCAP NetFlow v5 exporter (p2nprobe)
    Date: 18.11.2024

    Author: Tomáš Bordák [xborda01]
*/

#include "pcap_functions.h"
#include "flow_functions.h"
#include "export_functions.h"

extern flow_t *flows;
extern int flowsLength;

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
