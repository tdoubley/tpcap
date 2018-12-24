#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "debug.h"

#include "src/pcap/protocol.h"
#include "src/pcap/pcap.h"
#include "src/utils/utlist.h"

#include "src/pcap/pcap_parser.h"


int pcap_parser(pcap_t *pcap, const char *path) {
    FILE *fp = fopen(path, "rw");
    if (fp == NULL) {
        return -1;
    }

    DEBUG_PRINT("%s\n", "pcap parser\n");

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
        //LL_APPEND(pcap->packets, packet_node);
        //free(packet_node->data);
        //free(packet_node);
    }

    return packet_count;
}

int pcap_analyse(pcap_t *pcap) {
    DEBUG_PRINT("%s\n", "pcap analyse");

    int ret = 0;
    pcap_packet_node_t *head = pcap->packets;
    pcap_packet_node_t *node = NULL;
    LL_FOREACH(head, node) {
        /* ethernet报文解析 */
        eth_packet_node_t *peth_packet = malloc(sizeof(eth_packet_node_t));
        memset(peth_packet, 0, sizeof(eth_packet_node_t));
        int ret = eth_analyse(pcap, node->data, peth_packet);
        if (ret == 0) { /* 解析成功添加Ethernet链表 */
            LL_PREPEND(pcap->eth_packets, peth_packet);
            pcap->eth_packet_count++;
        } else {
            free(peth_packet);
        }
    }

    return 0;
}

int eth_analyse(pcap_t *pcap, u_char *packet, eth_packet_node_t *eth_packet) {
    DEBUG_PRINT("%s\n", "ethernet analyse");

    eth_header_t *header = (eth_header_t *)packet;

    /* 网络字节序到主机字节序 */
    eth_header_ntoh(header);

    /* header */
    eth_packet->header = header;
    /* data */
    eth_packet->pdata = (packet + ETH_HEADER_LENGTH);

    switch (header->proto) {
        case ETH_P_ARP:
        {}
        break;
        case ETH_P_IP:
        {
            ip_packet_node_t *pip_packet = (ip_packet_node_t *)malloc(sizeof(ip_packet_node_t));
            memset(pip_packet, 0, sizeof(ip_packet_node_t));
            int ret = ip_analyse(pcap, eth_packet->pdata, pip_packet);
            if (ret == 0) { /* 解析成功添加IP链表中 */
                LL_PREPEND(pcap->ip_packets , pip_packet);
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
    DEBUG_PRINT("%s\n", "pcap IP analyse");

    ip_header_t *header = (ip_header_t *)packet;

    /* 网络字节序到主机字节序 */
    ip_header_ntoh(header);

    /* header */
    ip_packet->header = header;
    /* data */
    if (contain_options(header) >= 0) {
        //带有OPTIONS的IP header暂不处理
    } else {
        ip_packet->pdata = (packet + IP_HEADER_LENGTH - 4); /* 减去OPTIONS的长度 */
    }

    switch (header->proto) {
        case IP_P_TCP:
        {
            DEBUG_PRINT("%s\n", "TCP packet analyse");
            
            tcp_packet_node_t *ptcp_packet = (tcp_packet_node_t *)malloc(sizeof(tcp_packet_node_t));
            memset(ptcp_packet, 0, sizeof(tcp_packet_node_t));
            int ret = tcp_analyse(pcap, ip_packet->pdata, ptcp_packet);
            if (ret == 0) { /* 解析成功添加TCP链表中 */
                LL_PREPEND(pcap->tcp_packets, ptcp_packet);
                pcap->tcp_packet_count++;
            }
        }
        break;
        case IP_P_UDP:
        {
            DEBUG_PRINT("%s\n", "UDP packet analyse");

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
    DEBUG_PRINT("%s\n", "pcap TCP analyse");

    tcp_header_t *header = (tcp_header_t *)packet;

    /* 网络字节序到主机字节序 */
    tcp_header_ntoh(header);

    /* header */
    tcp_packet->header = header;
    /* data */
    tcp_packet->pdata = (packet + TCP_HEADER_LENGTH);

    return 0;
}

int udp_analyse(pcap_t *pcap, u_char *packet, udp_packet_node_t *udp_packet) {
    DEBUG_PRINT("%s\n", "pcap UDP analyse");

    udp_header_t *header = (udp_header_t *)packet;

    /* 网络字节序到主机字节序 */
    udp_header_ntoh(header);

    /* header */
    udp_packet->header = header;
    /* data */
    udp_packet->pdata = (packet + TCP_HEADER_LENGTH);

    return 0;
}


void pcap_print(pcap_t *pcap) {
    if (pcap == NULL) {
        return;
    }

    pcap_packet_node_t *head = pcap->packets;
    pcap_packet_node_t *node = NULL;

    LL_FOREACH(head, node) {
         packet_header_print(&node->header);
    }
}

void pcap_eth_print(pcap_t *pcap) {
    if (pcap == NULL) {
        return;
    }

    eth_packet_node_t *head = pcap->eth_packets;
    eth_packet_node_t *node = NULL;

    LL_FOREACH(head, node) {
        eth_header_print(node->header);
    }

    return;
}

void pcap_ip_print(pcap_t *pcap) {
    ip_packet_node_t *head = pcap->ip_packets;
    ip_packet_node_t *node = NULL;

    LL_FOREACH(head, node) {
        ip_header_print(node->header);
    }

    return;
}

void pcap_tcp_print(pcap_t *pcap) {
    tcp_packet_node_t *head = pcap->tcp_packets;
    tcp_packet_node_t *node = NULL;

    LL_FOREACH(head, node) {
        tcp_header_print(node->header);
    }

    return;
}

void pcap_udp_print(pcap_t *pcap) {
    udp_packet_node_t *head = pcap->udp_packets;
    udp_packet_node_t *node = NULL;

    LL_FOREACH(head, node) {
        udp_header_print(node->header);
    }

    return;
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

int pcap_free(pcap_packet_node_t* head) {
    pcap_packet_node_t *node = NULL;
    pcap_packet_node_t *tmp = NULL;

    LL_FOREACH_SAFE(head, node, tmp) {
        pcap_free_node(node);
    }

    return 0;
}
