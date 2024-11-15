#ifndef FUNCTIONS_H

#define MAX_HOSTS 256
#define NO_ERROR 0
#define ERROR 1

typedef struct
{
    char host[MAX_HOSTS];
    char *pcapFilePath;
    int port;
    int activeTimout;
    int inactiveTimout;
} config_t;

void printUsage(int error);
config_t parseArgs(int argc, char *argv[]);
#endif