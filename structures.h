/*
    [ISA project] - PCAP NetFlow v5 exporter (p2nprobe)
    Date: 18.11.2024

    Author: Tomáš Bordák [xborda01]
*/

#ifndef STRUCTURES_H
#include <netinet/ip.h> // INET_ADDRSTRLEN
#include <unistd.h>

/*
    program arguments structure
*/
typedef struct
{
    char host[256];
    char *pcapFilePath;
    int port;
    int activeTimeout;
    int inactiveTimeout;
} config_t;

/*
    structure for each flow
*/
typedef struct
{
    char srcIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    uint16_t srcPORT;
    uint16_t destPORT;
    int packetCount;
    int bytesCount;
    struct timeval first;
    struct timeval last;
} flow_t;

/*
    almost the same as flow_t, but for packet data that are needed to create a new flow or update existing one
*/
typedef struct
{
    char srcIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    uint16_t srcPORT;
    uint16_t destPORT;
    int bytes;
    struct timeval timestamp;
} packet_t;

/*
    NETFLOW v5 HEADER FORMAT
    variable type based on how many bytes header field needs
    https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006108 [16.11.2024]
    sum: 24 bytes
*/
typedef struct
{
    uint16_t version;       // version 5
    uint16_t count;         // number of flows exported in this packet (1-30)
    uint32_t SysUptime;     // current time - boot time in miliseconds
    uint32_t unix_secs;     // current time in seconds since 0000 UTC 1970
    uint32_t unix_nsecs;    // current time in nanoseconds since 0000 UTC 1970
    uint32_t flow_sequence; // sequenceCount
    uint8_t engine_type;
    uint8_t engine_id;
    uint16_t sampling_interval;

} NetFlow_v5_header_t;

/*
    NETFLOW v5 FLOW RECORD FORMAT
    https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006186 [16.11.2024]
    sum: 48 bytes
*/
typedef struct
{
    uint32_t srcaddr; // source IP addr
    uint32_t dstaddr; // destination IP addr
    uint32_t nexthop;
    uint16_t input;
    uint16_t output;
    uint32_t dPkts;   // flow packet count
    uint32_t dOctets; // flow byte count
    uint32_t First;   // first packet time - boot time (in miliseconds)
    uint32_t Last;    // last packet time - boot time (in miliseconds)
    uint16_t srcport; // TCP source port
    uint16_t dstport; // TCP destination port
    uint8_t pad1;
    uint8_t tcp_flags;
    uint8_t prot; // TCP = 6
    uint8_t tos;
    uint16_t src_as;
    uint16_t dst_as;
    uint8_t src_mask; // 32
    uint8_t dst_mask; // 32
    uint16_t pad2;
} NetFlow_v5_record_t;

#endif