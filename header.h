#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<libnet.h>
#include<pcap.h>
#include<pthread.h>

#define MAXLINE 256
#define ETH_ALEN 6
#define IP_ALEN 4

// used send_arp
typedef struct spoof_table{
    u_char eth_src[ETH_ALEN];
    u_char eth_dst[ETH_ALEN];
    u_char ip_src[IP_ALEN];
    u_char ip_dst[IP_ALEN];
}spoof_t;

typedef struct addr_table {
    uint32_t ip_victim;
    uint32_t ip_me;
    uint32_t ip_gateway;
    uint8_t  mac_victim[ETH_ALEN];
    uint8_t  mac_me[ETH_ALEN];
    uint8_t  mac_gateway[ETH_ALEN];
}addr_t;

// used deliver packet
typedef struct ether_header
{
    u_char dst_host[IP_ALEN];
    u_char src_host[IP_ALEN];
    u_short frame_type;
}ether_header;

typedef struct ip_header
{
    u_char ver_ihl; // Version (4 bits) + Internet header length (4 bits)
    u_char tos; // Type of service
    u_short tlen; // Total length
    u_short identification; // Identification
    u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
    u_char ttl; // Time to live
    u_char proto; // Protocol
    u_short crc; // Header checksum
    u_char saddr[4]; // Source address
    u_char daddr[4]; // Destination address
    u_int op_pad; // Option + Padding
}ip_header;

typedef struct tcp_header
{
    u_short sport; // Source port
    u_short dport; // Destination port
    u_int seqnum; // Sequence Number
    u_int acknum; // Acknowledgement number
    u_char hlen; // Header length
    u_char flags; // packet flags
    u_short win; // Window size
    u_short crc; // Header Checksum
    u_short urgptr; // Urgent pointer...still don't know what this is...
}tcp_header;

// used func
void set_addr(addr_t *table, char *victim_ip);
void handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

// used thread
void *thread1_send_arp(void *arg);
void *thread2_deliver_packet(void *arg);
