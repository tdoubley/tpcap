#ifndef _TPACAP_SRC_PCAP_PARSER_H_
#define _TPCAP_SRC_PCAP_PARSER_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "src/pcap/pcap.h"
#include "src/protocol/protocol.h"


int pcap_parser(pcap_t *pcap, const char *path);
int pcap_analyse(pcap_t *pcap);
int pcap_free(pcap_packet_node_t* head);


int pacp_get_eth_packets(pcap_t *pcap);
int pacp_get_ip_packets(pcap_t *pcap);
int pacp_get_tcp_packets(pcap_t *pcap);
int pacp_get_udp_packets(pcap_t *pcap);


void pcap_print(pcap_t *pcap);
void pcap_eth_print(pcap_t *pcap);
void pcap_ip_print(pcap_t *pcap);
void pcap_tcp_print(pcap_t *pcap);
void pcap_udp_print(pcap_t *pcap);





#endif /* _TPACAP_SRC_PCAP_PARSER_H_ */

