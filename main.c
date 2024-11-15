#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>

#include "functions.h"
#include "pcap_functions.h"

int main(int argc, char *argv[])
{
    config_t config;
    pcap_t *pcapHandle;

    config = parseArgs(argc, argv);

    pcapHandle = createHandle(config.pcapFilePath);
    printf("Handle succesfully created.\n");

    return 0;
}
