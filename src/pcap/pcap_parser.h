#ifndef _SRC_PCAP_LOAD_H_
#define _SRC_PCAP_LOAD_H_

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

typedef struct pcap_file_header {
    uint32_t magic;
    u_short version_major;
    u_short version_minor;
    uint32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
}pcap_file_header_t;

/*
 Packet 包头和Packet数据组成
 字段说明：
 Timestamp：时间戳高位，精确到seconds
 Timestamp：时间戳低位，精确到microseconds
 Caplen：当前数据区的长度，即抓取到的数据帧长度，由此可以得到下一个数据帧的位置。
 Len：离线数据长度：网络中实际数据帧的长度，一般不大于caplen，多数情况下和Caplen数值相等。
 Packet 数据：即 Packet（通常就是链路层的数据帧）具体内容，长度就是Caplen，这个长度的后面，就是当前PCAP文件中存放的下一个Packet数据包，也就 是说：PCAP文件里面并没有规定捕获的Packet数据包之间有什么间隔字符串，下一组数据在文件中的起始位置。我们需要靠第一个Packet包确定。
 */

typedef struct  timestamp{
    uint32_t timestamp_s;
    uint32_t timestamp_ms;
}timestamp_t;

typedef struct pcap_packet_header{
    timestamp_t ts;
    uint32_t  capture_len;
    uint32_t  len;
}pcap_packet_header_t;

typedef struct pcap_packet_node {
    pcap_packet_header_t header;
    u_char  *data;
    struct pcap_packet_node *next;
}pcap_packet_node_t;

typedef struct pcap {
    pcap_file_header_t file_header;
    pcap_packet_node_t *packets;
}pcap_t;


int pcap_init(pcap_t **pcap);
int pcap_finish(pcap_t *pcap);
int pcap_parser(pcap_t *pcap, const char *path);
//void pcap_file_header_out(const pcap_file_header_t *pfh);
//void pcap_packet_header_out(const pcap_packet_header_t *pfh);
void pcap_out(void *handle);
void pcap_packet_node_out(pcap_packet_node_t *node);
void pcap_free_node(pcap_packet_node_t* packet_node);
void pcap_free(pcap_packet_node_t* head);


#endif /* end of _SRC_PCAP_LOAD_H_ */

