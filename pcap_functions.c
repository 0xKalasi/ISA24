#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>

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
