#include "src/pcap/pcap_parser.h"


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "debug.h"

#include "src/pcap/protocol.h"
#include "src/utils/utlist.h"

int pcap_init(pcap_t **ppcap) {
    if (ppcap == NULL) {
        return -1;
    }

    pcap_t *pcap = (pcap_t *)malloc(sizeof(pcap_t));
    if (pcap == NULL) {
        return -1;
    }
    memset(pcap, 0, sizeof(pcap_t));
    *ppcap = pcap;

    DEBUG_PRINT("%s", "pcap initial\n");

    return 0;
}

int pcap_finish(pcap_t *pcap) {
    if (pcap == NULL) {
        return -1;
    }

    pcap_free(((pcap_t *)pcap)->packets);

    DEBUG_PRINT("%s", "pcap finished\n");

    return 0;
}

int pcap_parser(pcap_t *pcap, const char *path) {
    FILE *fp = fopen(path, "rw");
    if (fp == NULL) {
        return -1;
    }

    int packet_count = 0;
    int read_count = 0;

    /* 读取文件头 */
    read_count = fread(&pcap->file_header, sizeof(pcap_file_header_t), 1, fp);
    if (read_count <= 0) {
        return -1;
    }

    DEBUG_PRINT("pcap file header:"
                "=====================\n"
                "magic:0x%0x\n"
                "version_major:%u\n"
                "version_minor:%u\n"
                "thiszone:%d\n"
                "sigfigs:%u\n"
                "snaplen:%u\n"
                "linktype:%u\n"
                "=====================\n",
                pcap->file_header.magic,
                pcap->file_header.version_major,
                pcap->file_header.version_minor,
                pcap->file_header.thiszone,
                pcap->file_header.sigfigs,
                pcap->file_header.snaplen,
                pcap->file_header.linktype);

    while(1) {
        pcap_packet_node_t *packet_node = (pcap_packet_node_t *)malloc(sizeof(pcap_packet_node_t));
        if (packet_node == NULL) {
            break;
        }
        memset(packet_node, 0, sizeof(pcap_packet_node_t));

        /* 读取包头 */
        read_count = fread(&packet_node->header, sizeof(pcap_packet_header_t), 1, fp);
        if (read_count <= 0) {
            pcap_free_node(packet_node);
            break;
        }

        /* 读取包数据 */
        uint32_t buf_len = packet_node->header.capture_len;
        u_char *buf = (u_char *)malloc(buf_len);
        read_count = fread(buf, 1, buf_len, fp);
        if (read_count != buf_len) {
            pcap_free_node(packet_node);
            free(buf);
            break;
        } else {
            packet_node->data = buf;
        }

        packet_count++;

        LL_PREPEND(pcap->packets, packet_node);

//        DEBUG_PRINT("packet %d header:"
//            "=====================\n"
//            "ts.timestamp_s:%u\n"
//            "ts.timestamp_ms:%u\n"
//            "capture_len:%u\n"
//            "len:%d\n"
//            "=====================\n",
//            packet_count,
//            packet_node->header.ts.timestamp_s,
//            packet_node->header.ts.timestamp_ms,
//            packet_node->header.capture_len,
//            packet_node->header.len);
    }

    return packet_count;
}

int pcap_analyse(pcap_t *pcap) {
    int ret = 0;
    pcap_packet_node_t *head = pcap->packets;
    pcap_packet_node_t *node = NULL;
    LL_FOREACH(head, node) {
        /* 解析原始报文中的所有IP报文 */

        /* 1. ethernet报文解析 */
        eth_packet_node_t *peth_packet = malloc(sizeof(eth_packet_node_t));
        int ret = eth_analyse(pcap, node->data, peth_packet);
        if (ret == 0) { /* 解析成功添加Ethernet链表 */
            LL_APPEND(pcap->eth_packets, peth_packet);
            pcap->eth_packet_count++;
        } else {
            free(peth_packet);
        }
    }

    return 0;
}

int eth_analyse(pcap_t *pcap, u_char *packet, eth_packet_node_t *eth_packet) {
    eth_header_t *header = &eth_packet->header;

    /* 网络字节序到主机字节序 */
    header = (eth_header_t *)(packet);
    header->proto = ntohs(header->proto);
    /* 保存数据 */
    eth_packet->pdata = (packet + ETH_HEADER_LENGTH);

    switch (header->proto) {
        case ETH_P_ARP:
        {}
        break;
        case ETH_P_IP:
        {
            ip_packet_node_t *pip_packet = (ip_packet_node_t *)malloc(sizeof(ip_packet_node_t));
            int ret = ip_analyse(pcap, eth_packet->pdata, pip_packet);
            if (ret == 0) { /* 解析成功添加IP链表中 */
                LL_APPEND(pcap->ip_packets , pip_packet);
                pcap->ip_packet_count++;
            }
        }
        break;
        case ETH_P_IPV6:
        {}
        break;
        case ETH_P_RARP:
        {}
        break;
        default:
        break;
    }

    return 0;
}


int ip_analyse(pcap_t *pcap, u_char *packet, ip_packet_node_t *ip_packet) {
    ip_header_t *header = &ip_packet->header;

    /* 网络字节序到主机字节序 */
    header = (ip_header_t *)(packet);
    header->ver_ihl = ntohs(header->ver_ihl);
    header->tox = ntohs(header->tox);
    header->tlen = ntohs(header->tlen);
    header->identification = ntohs(header->identification);
    header->flags_fo = ntohs(header->flags_fo);
    header->ttl = ntohs(header->ttl);
    header->tlen = ntohs(header->tlen);
    header->proto = ntohs(header->proto);
    header->crc = ntohs(header->crc);
    //header->src_addr = ntohs(header->src_addr);
    //header->dst_addr = ntohs(header->dst_addr);
    header->op_pad = ntohs(header->op_pad);

    /* data */
    ip_packet->pdata = (packet + IP_HEADER_LENGTH);

    DEBUG_PRINT("IP layer protocol: %d\n", header->proto);

    switch (header->proto) {
        case IP_P_TCP:
        {
            DEBUG_PRINT("%s", "TCP packet analyse\n");

            tcp_packet_node_t *ptcp_packet = (tcp_packet_node_t *)malloc(sizeof(tcp_packet_node_t));
            int ret = tcp_analyse(pcap, ip_packet->pdata, ptcp_packet);
            if (ret == 0) { /* 解析成功添加TCP链表中 */
                LL_APPEND(pcap->tcp_packets, ptcp_packet);
                pcap->tcp_packet_count++;
            }
        }
        break;
        case IP_P_UDP:
        {
            udp_packet_node_t *pudp_packet = (udp_packet_node_t *)malloc(sizeof(udp_packet_node_t));
            int ret = udp_analyse(pcap, ip_packet->pdata, pudp_packet);
            if (ret == 0) { /* 解析成功添加UDP链表中 */
                LL_APPEND(pcap->udp_packets, pudp_packet);
                pcap->udp_packet_count++;
            }
        }
        break;
        default:
        break;
    }

    return 0;
}

int tcp_analyse(pcap_t *pcap, u_char *packet, tcp_packet_node_t *tcp_packet) {
    tcp_header_t *header = &tcp_packet->header;

    /* 网络字节序到主机字节序 */
    header = (tcp_header_t *)(packet);
    header->src_port = ntohs(header->src_port);
    header->dst_port = ntohs(header->dst_port);
    header->seq_number = ntohs(header->seq_number);
    header->ack_number = ntohs(header->ack_number);
    header->info_ctrl = ntohs(header->info_ctrl);
    header->window = ntohs(header->window);
    header->checksum = ntohs(header->checksum);
    header->urgent_pointer = ntohs(header->urgent_pointer);

    /* data */
    tcp_packet->pdata = (packet + TCP_HEADER_LENGTH);

    return 0;
}

int udp_analyse(pcap_t *pcap, u_char *packet, udp_packet_node_t *udp_packet) {
    udp_header_t *header = &udp_packet->header;

    /* 网络字节序到主机字节序 */
    header = (udp_header_t *)(packet);
    header->src_port = ntohs(header->src_port);
    header->dst_port = ntohs(header->dst_port);
    header->length = ntohs(header->length);
    header->ack_number = ntohs(header->ack_number);

    /* data */
    udp_packet->pdata = (packet + TCP_HEADER_LENGTH);

    return 0;
}


void pcap_file_header_out(const pcap_file_header_t *pfh)
{
    if (pfh==NULL) {
        return;
    }

    printf("=====================\n"
           "magic:0x%0x\n"
           "version_major:%u\n"
           "version_minor:%u\n"
           "thiszone:%d\n"
           "sigfigs:%u\n"
           "snaplen:%u\n"
           "linktype:%u\n"
           "=====================\n",
           pfh->magic,
           pfh->version_major,
           pfh->version_minor,
           pfh->thiszone,
           pfh->sigfigs,
           pfh->snaplen,
           pfh->linktype);
}

void pcap_packet_header_out(const pcap_packet_header_t *ph) {
    if (ph==NULL) {
        return;
    }

    printf("=====================\n"
           "ts.timestamp_s:%u\n"
           "ts.timestamp_ms:%u\n"
           "capture_len:%u\n"
           "len:%d\n"
           "=====================\n",
           ph->ts.timestamp_s,
           ph->ts.timestamp_ms,
           ph->capture_len,
           ph->len);

    return;
}

void pcap_out(pcap_t *pcap) {
    if (pcap == NULL) {
        return;
    }

    pcap_packet_node_t *head = pcap->packets;
    pcap_packet_node_t *node = NULL;

    LL_FOREACH(head, node) {
        pcap_packet_node_out(node);
    }
}

void pcap_print_tcp(pcap_t *pcap) {
    tcp_packet_node_t *head = pcap->tcp_packets;
    tcp_packet_node_t *node = NULL;

    LL_FOREACH(head, node) {
        printf("=====================\n"
           "source port:%d\n"
           "dest port:%d\n"
           "sequence number:%d\n"
           "acknowledge number:%d\n"
           "data offset:%d\n"
           "reserved:%d\n"
           "control bits:%d\n"
           "window:%d\n"
           "checksum:%d\n"
           "urgent_pointer:%d\n"
           "=====================\n",
           node->header.src_port,
           node->header.dst_port,
           node->header.seq_number,
           node->header.ack_number,
           (node->header.info_ctrl >> 12) & (1<<4),
           (node->header.info_ctrl >> 6) & (1<<6),
           (node->header.info_ctrl)  & (1<<6),
           node->header.window,
           node->header.checksum,
           node->header.urgent_pointer);
    }

    return;
}


void pcap_packet_node_out(pcap_packet_node_t *node) {
    if (node == NULL) {
        return;
    }

    pcap_packet_header_out(&node->header);
}

void pcap_free_node(pcap_packet_node_t* packet_node) {
    if (packet_node == NULL) {
        return;
    }

    if (packet_node->data != NULL) {
        free(packet_node->data);
    }

    free(packet_node);
}

void pcap_free(pcap_packet_node_t* head) {
    pcap_packet_node_t *node = NULL;
    pcap_packet_node_t *tmp = NULL;
    LL_FOREACH_SAFE(head, node, tmp) {
        pcap_free_node(node);
    }
}
