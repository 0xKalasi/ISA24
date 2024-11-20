/*
    [ISA project] - PCAP NetFlow v5 exporter (p2nprobe)
    Date: 18.11.2024

    Author: Tomáš Bordák [xborda01]
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

void printUsage(int error)
{
    if (!error)
    {
        printf("Usage: ./p2nprobe <host>:<port> <pcap_file_path> [-a <active_timeout> -i <inactive_timeout> -h]\n\n");
        printf("    <host> -> IP address or domain name of collector\n");
        printf("    <port> -> collector port (range 0 to 65535)\n");
        printf("    <active_timeout> -> number of seconds to set as active timeout for the flow export (default value is 60)\n");
        printf("    <inactive_timeout> -> number of seconds to set as inactive timeout for the flow export (default value is 60)\n");

        exit(0);
    }
    else
    {
        fprintf(stderr, "Usage: ./p2nprobe <host>:<port> <pcap_file_path> [-a <active_timeout> -i <inactive_timeout> -h]\n");
        exit(1);
    }
}

config_t parseArgs(int argc, char *argv[])
{
    config_t config;

    // DEFAULT VALUES
    config.activeTimeout = 60;
    config.inactiveTimeout = 60;

    // so I can then check if it was parsed
    config.port = -1;
    config.pcapFilePath = NULL;

    char host[256];
    int port;

    // go through all of arguments, because for some reason the way I used getopt and optind didnt work on merlin (BSD linux), I work on mac
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-h") == 0)
            printUsage(NO_ERROR);

        else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc)
        {
            config.activeTimeout = atoi(argv[++i]);
            if (config.activeTimeout <= 0)
            {
                fprintf(stderr, "ERROR: -a <active_timeout> must be a number greater than 0. Use -h for usage.\n");
                exit(ERROR);
            }
        }

        else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc)
        {
            config.inactiveTimeout = atoi(argv[++i]);
            if (config.inactiveTimeout <= 0)
            {
                fprintf(stderr, "ERROR: -i <inactive_timeout> must be a number greater than 0. Use -h for usage.\n");
                exit(ERROR);
            }
        }

        // <host>:<port>
        else if (sscanf(argv[i], "%255[^:]:%d", host, &port) == 2)
        {
            strcpy(config.host, host);

            if (port > 65535 || port < 0)
            {
                fprintf(stderr, "ERROR: <port> needs to be in range of 0 to 65535. Use -h for usage.\n");
                exit(1);
            }
            else
                config.port = port;
        }

        // <pcap_file_path>
        else if (!config.pcapFilePath)
            config.pcapFilePath = argv[i];

        else
            printUsage(ERROR);
    }

    // check mandatory arguments
    if (!config.pcapFilePath || config.port == -1)
    {
        fprintf(stderr, "ERROR: arguments <file> and <host>:<port> are mandatory\n");
        exit(ERROR);
    }

    return config;
}
