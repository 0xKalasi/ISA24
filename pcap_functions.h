/*
    [ISA project] - PCAP NetFlow v5 exporter (p2nprobe)
    Date: 18.11.2024

    Author: Tomáš Bordák [xborda01]
*/

#ifndef PCAP_FUNCTIONS_H

#include <stdio.h>
#include <stdlib.h>

#include <pcap/pcap.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

/*
    open pcap file with pcap_open_offline and return file handle
*/
pcap_t *createHandle(const char *file);

/*
    uses pcap_close to safely close file handle
*/
void closeHandle(pcap_t *pcapHandle);

/*
    callback function for pcap_loop().

    gets called for every packet

    ignores packets that are not TCP packets
*/
void packetHandler(u_char *userData, const struct pcap_pkthdr *header, const u_char *packet);

#endif