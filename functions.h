#ifndef FUNCTIONS_H

typedef struct
{
    char host[256];
    char *pcap_file_path;
    int port;
    int active_timout;
    int inactive_timout;
} config_t;

config_t parseArgs(int argc, char *argv[]);
#endif