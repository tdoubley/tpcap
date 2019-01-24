#ifndef _TPCAP_SRC_PCAP_H_
#define _TPCAP_SRC_PCAP_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "src/protocol/protocol.h"

/*
 Pcap文件头24B各字段说明：
 Magic：4B：0x1A 2B 3C 4D:用来标示文件的开始
 Major：2B，0x02 00:当前文件主要的版本号     
 Minor：2B，0x04 00当前文件次要的版本号
 ThisZone：4B当地的标准时间；全零
 SigFigs：4B时间戳的精度；全零
 SnapLen：4B最大的存储长度    
 LinkType：4B链路类型
 常用类型：
 　0            BSD loopback devices, except for later OpenBSD
 1            Ethernet, and Linux loopback devices
 6            802.5 Token Ring
 7            ARCnet
 8            SLIP
 9            PPP
 */

/* pcap 报文头格式 */
#pragma pack(1)
typedef struct pcap_file_header {
    uint32_t magic;        /* 用来标示文件的开始 */
    u_short version_major; /* 当前文件主要的版本号 */
    u_short version_minor; /* 当前文件次要的版本号 */
    uint32_t thiszone;     /* 当地的标准时间；全零 */
    uint32_t sigfigs;      /* accuracy of timestamps */
    uint32_t snaplen;      /* max length saved portion of each pkt */
    uint32_t linktype;     /* data link type */
}pcap_file_header_t;

typedef struct  timestamp{
    uint32_t timestamp_s;
    uint32_t timestamp_ms;
}timestamp_t;

/*
 Packet 包头和Packet数据组成
 字段说明：
 Timestamp：时间戳高位，精确到seconds
 Timestamp：时间戳低位，精确到microseconds
 Caplen：当前数据区的长度，即抓取到的数据帧长度，由此可以得到下一个数据帧的位置。
 Len：离线数据长度：网络中实际数据帧的长度，一般不大于caplen，多数情况下和Caplen数值相等。
 Packet 数据：即 Packet（通常就是链路层的数据帧）具体内容，长度就是Caplen，这个长度的后面，就是当前PCAP文件中存放的下一个Packet数据包，也就 是说：PCAP文件里面并没有规定捕获的Packet数据包之间有什么间隔字符串，下一组数据在文件中的起始位置。我们需要靠第一个Packet包确定。
 */
typedef struct pcap_packet_header{
    timestamp_t ts;
    uint32_t    capture_len; /* length of portion present */
    uint32_t    len;         /* length this packer(off wire) */
}pcap_packet_header_t;

#pragma pack()


/* raw packets nodes */
typedef struct pcap_packet_node {
    pcap_packet_header_t header;
    u_char  *data;
    uint32_t len;
    struct pcap_packet_node *next;
}pcap_packet_node_t;

/* ethernet packet nodes */
typedef struct eth_packet_node {
    eth_header_t *header;
    u_char *pdata;
    uint32_t len;
    struct eth_packet_node *next;
}eth_packet_node_t;

/* ip packet nodes */
typedef struct ip_packet_node {
    ip_header_t *header;
    u_char      *pdata;
    uint32_t     len;
    struct ip_packet_node *next;
}ip_packet_node_t;

/* tcp packet nodes */
typedef struct tcp_packet_node {
    tcp_header_t *header;
    u_char       *pdata;
    uint32_t      len;
    app_proto_data_t *app_data;
    struct tcp_packet_node *next;
}tcp_packet_node_t;

/* udp packet nodes */
typedef struct udp_packet_node {
    udp_header_t *header;
    u_char       *pdata;
    uint32_t      len;
    app_proto_data_t *app_data;
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



void file_header_print(pcap_file_header_t *header);
void packet_header_print(pcap_packet_header_t *header);

#endif // _TPCAP_SRC_PCAP_H_
 
