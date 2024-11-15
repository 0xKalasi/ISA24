#ifndef PCAP_FUNCTIONS_H

pcap_t *createHandle(const char *file);

void loopFile(pcap_t *pcapHandle);

void packetHandler(u_char *userData, const struct pcap_pkthdr *header, const u_char *packet);

#endif