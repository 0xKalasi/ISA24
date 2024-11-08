#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <getopt.h>

#include "functions.h"

config_t parseArgs(int argc, char *argv[])
{
    config_t config;

    // DEFAULT VALUES
    config.active_timout = 60;
    config.inactive_timout = 60;

    int opt;
    opterr = 0; // internal getopt.h flag, 0 means getopt() wont print error messages, since I want to print them myself

    while (optind < argc)
    {
        if ((opt = getopt(argc, argv, "i:a:?")) != -1)
        {
            // argument is option
            switch (opt)
            {
            case 'i':
                // -i -a -> here optarg for i will be -a -> error
                if (optarg[0] == '-' || (config.inactive_timout = atoi(optarg)) == 0)
                {
                    fprintf(stderr, "ERROR: Option -%c requires number as argument.\n", opt);
                    exit(1);
                }
                break;
            case 'a':
                if (optarg[0] == '-' || (config.active_timout = atoi(optarg)) == 0)
                {
                    fprintf(stderr, "ERROR: Option -%c requires number as argument.\n", opt);
                    exit(1);
                }
                break;
            case '?':
                if (optopt == 'i' || optopt == 'a')
                {
                    fprintf(stderr, "ERROR: Option -%c requires an argument.\n", optopt);
                    exit(1);
                }
                else
                {
                    fprintf(stderr, "ERROR: Unkown option -%c\n", optopt);
                    exit(1);
                }
                break;
            }
        }
        else
        {
            // regular argument - <host>:<port> and <pcap_file_path>

            // variables to store into in the next if statement
            char host[256];
            int port;

            if (sscanf(argv[optind], "%255[^:]:%d", host, &port) == 2)
            {
                strcpy(config.host, host);
                config.port = port;
            }
            else
                config.pcap_file_path = argv[optind]; // its not <host>:<path> so its <pcap_file_path>

            optind++; // move to next argument
        }
    }

    if (!config.pcap_file_path && !config.port)
    {
        fprintf(stderr, "ERROR: arguments <host>:<port> <pcap_file_path> are mandatory.\n");
        exit(1);
    }
    else if (!config.pcap_file_path)
    {
        fprintf(stderr, "ERROR: argument <pcap_file_path> is mandatory.\n");
        exit(1);
    }
    else if (!config.port)
    {
        fprintf(stderr, "ERROR: argument <host>:<port> is mandatory.\n");
        exit(1);
    }

    printf("config.host: '%s'\n", config.host);
    printf("config.port: '%d'\n", config.port);
    printf("config.pcap_file_path: '%s'\n", config.pcap_file_path);

    return config;
}
