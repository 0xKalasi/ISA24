/*
    [ISA project] - PCAP NetFlow v5 exporter (p2nprobe)
    Date: 18.11.2024

    Author: Tomáš Bordák [xborda01]
*/

#ifndef FUNCTIONS_H

#include "structures.h"

#define NO_ERROR 0
#define ERROR 1

void printUsage(int error);
config_t parseArgs(int argc, char *argv[]);
#endif