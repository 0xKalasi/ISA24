/*
    [ISA project] - PCAP NetFlow v5 exporter (p2nprobe)
    Date: 18.11.2024

    Author: Tomáš Bordák [xborda01]
*/

#include <stdio.h>
#include <pcap/pcap.h>
#include <unistd.h>

#include "common.h"
#include "export_functions.h"
#include "pcap_functions.h"

// GLOBAL VARIABLES
// extern <type> <variableName>; to use in other .c files
config_t config;

flow_t flowsToExport[30];
int flowsToExportLength = 0;

flow_t *flows = NULL;
int flowsLength = 0;

int socketDescriptor;
struct sockaddr_in collector;

struct timeval bootTime;

int sequenceCount = 0;

int main(int argc, char *argv[])
{
    // boot time ("export device booted time")
    gettimeofday(&bootTime, NULL);

    pcap_t *pcapHandle;

    config = parseArgs(argc, argv);

    pcapHandle = createHandle(config.pcapFilePath);

    initCollector();

    if (pcap_loop(pcapHandle, 0, packetHandler, NULL) == -1)
    {
        fprintf(stderr, "ERROR: processing packets: %s\n", pcap_geterr(pcapHandle));
        return 1;
    }

    exportRemaining();

    closeHandle(pcapHandle);
    close(socketDescriptor);

    return 0;
}
