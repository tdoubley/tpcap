#ifndef _SRC_PCAP_LOAD_H_
#define _SRC_PCAP_LOAD_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

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
    uint32_t magic;
    u_short version_major;
    u_short version_minor;
    uint32_t thiszone;
    uint32_t sigfigs;  /* accuracy of timestamps */
    uint32_t snaplen;  /* max length saved portion of each pkt */
    uint32_t linktype; /* data link type */
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
    uint32_t  capture_len; /* length of portion present */
    uint32_t  len; /* length this packer(off wire) */
}pcap_packet_header_t;


#define FRAME_IPTYPE 0x0800
/* 数据包头格式 */
typedef struct eth_header {
    u_char  srcmac[6]; /* 源MAC(6 bytes) */
    u_char  dstmac[6]; /* 目的MAC(6 bytes) */
    u_short proto;     /* 网络序(16 bits) */
}eth_header_t;
#pragma pack()

#define ETH_HEADER_LENGTH (sizeof(eth_header_t))


/* 4byte IP address */
typedef struct ip_address {
    u_char ucbyte1;
    u_char ucbyte2;
    u_char ucbyte3;
    u_char ucbyte4;
}ip_address_t;


/* IPV4 header */
typedef struct ip_header {
    u_char  ver_ihl;         /* Version(4 bits) + Internet header length(4 bits) */
    u_char  tox;             /* type of service */
    u_short tlen;            /* total length(16 bits) */
    u_short identification;  /* Identigication(16 bits) */
    u_short flags_fo;        /* Flags(3 bits) + Fragment offset(13 bits)*/
    u_char  ttl;             /* time to live(8 bits) */
    u_char  proto;           /* protocol(8 bits) */
    u_short crc;             /* header checksum(16 bits) */
    ip_address_t src_addr;   /* source addr */
    ip_address_t dst_addr;   /* dest addr */
    uint32_t op_pad;         /* option + padding() */
}ip_header_t;

#define IP_HEADER_LENGTH (sizeof(ip_header_t))

/* tcp header */
typedef struct tcp_header {
    u_short  src_port;       /* source port(16 bits) */
    u_short  dst_port;       /* dest port(16 bits) */
    uint32_t seq_number;     /* sequence number(32 bits) */
    uint32_t ack_number;     /* acknowledge number(32 bits) */
    u_short  info_ctrl;      /* data offset(4 bits) + reserved(6 bits) + control bits(6 bits) */
    u_short  window;         /* 16 bits */
    u_short  checksum;       /* 16 bits */
    u_short  urgent_pointer; /* 16 bits */
}tcp_header_t;

#define TCP_HEADER_LENGTH (sizeof(tcp_header_t))


/* udp header */
typedef struct udp_header {
    u_short src_port; /* 16 bits */
    u_short dst_port; /* 16 bits */
    u_short length; /* 16 bits */
    u_short ack_number; /* acknowledge number (16 bits) */
}udp_header_t;


typedef struct pcap_packet_node {
    pcap_packet_header_t header;
    u_char  *data;
    struct pcap_packet_node *next;
}pcap_packet_node_t;

/* ethernet packet nodes */
typedef struct eth_packet_node {
    eth_header_t header;
    u_char *pdata;
    struct eth_packet_node *next;
}eth_packet_node_t;


/* ip packet nodes */
typedef struct ip_packet_node {
    ip_header_t header;
    u_char      *pdata;
    struct ip_packet_node *next;
}ip_packet_node_t;

/* tcp packet nodes */
typedef struct tcp_packet_node {
    tcp_header_t header;
    u_char       *pdata;
    struct tcp_packet_node *next;
}tcp_packet_node_t;

/* udp packet nodes */
typedef struct udp_packet_node {
    udp_header_t header;
    u_char       *pdata;
    struct udp_packet_node *next;
}udp_packet_node_t;


/* raw packet nodes */
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
void pcap_out(pcap_t *pcap);
void pcap_print_tcp(pcap_t *pcap);

void pcap_packet_node_out(pcap_packet_node_t *node);
void pcap_free_node(pcap_packet_node_t* packet_node);
void pcap_free(pcap_packet_node_t* head);


#endif /* end of _SRC_PCAP_LOAD_H_ */

