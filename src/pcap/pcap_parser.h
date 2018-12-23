#ifndef _TPACAP_SRC_PCAP_PARSER_H_
#define _TPCAP_SRC_PCAP_PARSER_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "src/pcap/pcap.h"
#include "src/pcap/protocol.h"

/* raw packets nodes */
typedef struct pcap_packet_node {
    pcap_packet_header_t header;
    u_char  *data;
    struct pcap_packet_node *next;
}pcap_packet_node_t;

/* ethernet packet nodes */
typedef struct eth_packet_node {
    eth_header_t *header;
    u_char *pdata;
    struct eth_packet_node *next;
}eth_packet_node_t;

/* ip packet nodes */
typedef struct ip_packet_node {
    ip_header_t *header;
    u_char      *pdata;
    struct ip_packet_node *next;
}ip_packet_node_t;

/* tcp packet nodes */
typedef struct tcp_packet_node {
    tcp_header_t *header;
    u_char       *pdata;
    struct tcp_packet_node *next;
}tcp_packet_node_t;

/* udp packet nodes */
typedef struct udp_packet_node {
    udp_header_t *header;
    u_char       *pdata;
    struct udp_packet_node *next;
}udp_packet_node_t;

typedef struct pcap {
    pcap_file_header_t file_header;
    pcap_packet_node_t *packets;
    uint32_t packet_count;
    eth_packet_node_t *eth_packets;
    uint32_t eth_packet_count;
    ip_packet_node_t *ip_packets;
    uint32_t ip_packet_count;
    tcp_packet_node_t *tcp_packets;
    uint32_t tcp_packet_count;
    udp_packet_node_t *udp_packets;
    uint32_t udp_packet_count;
}pcap_t;


int pcap_init(pcap_t **pcap);
int pcap_finish(pcap_t *pcap);
int pcap_parser(pcap_t *pcap, const char *path);
int pcap_analyse(pcap_t *pcap);

int pacp_get_eth_packets(pcap_t *pcap);
int pacp_get_ip_packets(pcap_t *pcap);
int pacp_get_tcp_packets(pcap_t *pcap);
int pacp_get_udp_packets(pcap_t *pcap);

int eth_analyse(pcap_t *pcap, u_char *packet, eth_packet_node_t *eth_packet);
int ip_analyse(pcap_t *pcap, u_char *packet, ip_packet_node_t *ip_packet);
int tcp_analyse(pcap_t *pcap, u_char *packet, tcp_packet_node_t *tcp_packet);
int udp_analyse(pcap_t *pcap, u_char *packet, udp_packet_node_t *udp_packet);

void pcap_print(pcap_t *pcap);
void pcap_eth_print(pcap_t *pcap);
void pcap_ip_print(pcap_t *pcap);
void pcap_tcp_print(pcap_t *pcap);
void pcap_udp_print(pcap_t *pcap);


void pcap_free_node(pcap_packet_node_t* packet_node);
void pcap_free(pcap_packet_node_t* head);


#endif /* _TPACAP_SRC_PCAP_PARSER_H_ */

