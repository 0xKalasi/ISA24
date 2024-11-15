#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>

#include <netinet/ip.h>    // struct ip
#include <netinet/tcp.h>   // struct tcphdr
#include <netinet/ether.h> // struct ether_header
#include <arpa/inet.h>     // ntohs

#include "functions.h"
#include "pcap_functions.h"

int main(int argc, char *argv[])
{
    config_t config;
    pcap_t *pcapHandle;

    config = parseArgs(argc, argv);

    pcapHandle = createHandle(config.pcapFilePath);
    printf("Handle succesfully created.\n");

    loopFile(pcapHandle);

    return 0;
}
