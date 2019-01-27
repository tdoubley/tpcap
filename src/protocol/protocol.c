#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <netinet/in.h>

#include "tpcap/protocol.h"

inline void eth_header_ntoh(eth_header_t *header) {
    header->proto = ntohs(header->proto);
    return;
}

void eth_header_print(eth_header_t *header) {
    printf("%s", "Ethernet header:\n");
    u_char srcbuf[20] = {0};
    u_char dstbuf[20] = {0};
    sprintf(srcbuf, "%x-%x-%x-%x-%x-%x", header->srcmac[0], header->srcmac[1], header->srcmac[2], header->srcmac[3], 
    header->srcmac[4], header->srcmac[5]);
    sprintf(dstbuf, "%x-%x-%x-%x-%x-%x", header->dstmac[0], header->dstmac[1], header->dstmac[2], header->dstmac[3], 
    header->dstmac[4], header->dstmac[5]);

    printf("==========Ethernet header===========\n"
           "Source MAC: %s\n"
           "Dest MAC: %s\n"
           "Protocol: 0x%x\n",
           srcbuf,
           dstbuf,
           header->proto);

    return;
}

void ip_header_ntoh(ip_header_t *header) {
    header->tlen = ntohs(header->tlen);
    header->identification = ntohs(header->identification);
    header->flags_fo = ntohs(header->flags_fo);
    header->crc = ntohs(header->crc);
    if (contain_options(header) >= 0) {
        header->op_pad = ntohl(header->op_pad);
    }

    return;
}

void ip_header_print(ip_header_t *header) {
    u_char srcbuf[50] = {0};
    u_char dstbuf[50] = {0};

    sprintf(srcbuf, "%d.%d.%d.%d", header->src_addr.ucbyte1, header->src_addr.ucbyte2,
        header->src_addr.ucbyte3, header->src_addr.ucbyte4);
    sprintf(dstbuf, "%d.%d.%d.%d", header->dst_addr.ucbyte1, header->dst_addr.ucbyte2,
        header->dst_addr.ucbyte3, header->dst_addr.ucbyte4);

    printf("==========IP Header===========\n"
           "Version: %d\n"
           "Header length: %d\n"
           "Service type : %d\n"
           "Total lenght : %d\n"
           "Identification : 0x%x\n"
           "Flags : %d\n"
           "Fragment offset : %d\n"
           "TTL : %d\n"
           "Protocol : 0x%x\n"
           "Checksum : %d\n"
           "Source address : %s\n"
           "Destination address: %s\n"
           "Options: %d\n"
           "Padding: %d\n",
           header->version,
           header->ihl,
           header->tos,
           header->tlen,
           header->identification,
           (header->flags_fo >> 13) & (1<<4),
           (header->flags_fo) & (1<<13),
           header->ttl,
           header->proto,
           header->crc,
           srcbuf,
           dstbuf,
           0,
           0);

    return;
}

int contain_options(ip_header_t *header) {
    if (header->ihl == 5) {
        return -1;
    } else {
        return (header->ihl - 5 * 4);
    }
}


void tcp_header_ntoh(tcp_header_t *header) {
    header->src_port   = ntohs(header->src_port);
    header->dst_port   = ntohs(header->dst_port);
    header->seq_number = ntohl(header->seq_number);
    header->ack_number = ntohl(header->ack_number);
    header->window     = ntohs(header->window);
    header->checksum   = ntohs(header->checksum);
    header->urgent_pointer = ntohs(header->urgent_pointer);

    return;
}

void tcp_header_print(tcp_header_t *header) {
    printf("==========TCP Header===========\n"
           "Src port: %d\n"
           "Dst port: %d\n"
           "Sequesence number : %u\n"
           "Ack number : %u\n"
           "Header length : %d\n"
           "Flags : %d\n"
           "Windows size : %d\n"
           "Checksum : %d\n"
           "Urgent pointer : %d\n",
           header->src_port,
           header->dst_port,
           header->seq_number,
           header->ack_number,
           header->reserved_1,
           header->flags,
           header->window,
           header->checksum,
           header->urgent_pointer);

    return;
}

void udp_header_ntoh(udp_header_t *header) {
    header->src_port = ntohs(header->src_port);
    header->dst_port = ntohs(header->dst_port);
    header->length   = ntohs(header->length);
    header->checksum = ntohs(header->checksum);

    return;
}

void udp_header_print(udp_header_t *header) {
    printf("==========UDP Header===========\n"
           "Src port: %d\n"
           "Dst port: %d\n"
           "Length : %u\n"
           "Checksum : %u\n",
           header->src_port,
           header->dst_port,
           header->length,
           header->checksum);

    return;
}



