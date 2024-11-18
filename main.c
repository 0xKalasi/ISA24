#include <stdio.h>
#include <pcap/pcap.h>
#include <unistd.h>

#include "common.h"
#include "export_functions.h"
#include "pcap_functions.h"

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

int main(int argc, char *argv[])
{
    gettimeofday(&bootTime, NULL);
    /* printf("bootTime = %ld.%ld\n", bootTime.tv_sec, bootTime.tv_usec); */

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

    /* printf("Exported %d flows\n", sequenceCount); */

    closeHandle(pcapHandle);
    close(socketDescriptor);

    return 0;
}
