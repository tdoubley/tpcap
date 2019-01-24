#ifndef _SRC_PROTOCOL_PROTOCOL_H_
#define _SRC_PROTOCOL_PROTOCOL_H_

//#ifndef LITTLE_ENDIAN  
//#define LITTLE_ENDIAN   (1)   //BYTE ORDER  
//#else  
//#error Redefine LITTLE_ORDER  
//#endif

/* etnernet */
#define  ETH_P_IP    0x0800   //IP协议
#define  ETH_P_ARP   0x0806   //地址解析协议(Address Resolution Protocol)
#define  ETH_P_RARP  0x8035   //返向地址解析协议(Reverse Address Resolution Protocol)
#define  ETH_P_IPV6  0x86DD   //IPV6协议


/* IP */
#define IP_P_ICMP   1
#define IP_P_IGMP   3
#define IP_P_TCP    6
#define IP_P_EGP    8
#define IP_P_IGP    9
#define IP_P_UDP    17
#define IP_P_IPv6   41
#define IP_P_OSPF   89

typedef enum {
    APP_PROTO_NONE = 0,
    APP_PROTO_HTTP,
    APP_PROTO_MAX
}APP_PROTOCOL_E;

#pragma pack(1)

/* Ethernet header */
typedef struct eth_header {
    u_char  srcmac[6]; /* 源MAC(6 bytes) */
    u_char  dstmac[6]; /* 目的MAC(6 bytes) */
    u_short proto;     /* 网络序(16 bits) */
}eth_header_t;



/* 4byte IP address */
typedef struct ip_address {
    u_char ucbyte1;
    u_char ucbyte2;
    u_char ucbyte3;
    u_char ucbyte4;
}ip_address_t;

/* IPV4 header */
typedef struct ip_header {
    #if LITTLE_ENDIAN
    u_char ihl:4;
    u_char version:4;
    #else
    u_char version:4;
    u_char ihl:4;
    #endif
    u_char  tos;             /* type of service */
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


/* tcp header */
typedef struct tcp_header {
    u_short  src_port;       /* source port(16 bits) */
    u_short  dst_port;       /* dest port(16 bits) */
    uint32_t seq_number;     /* sequence number(32 bits) */
    uint32_t ack_number;     /* acknowledge number(32 bits) */
    #if LITTLE_ENDIAN
    u_char reserved_1:4;    /* Reserve */
    u_char thl:4;           /* tcp header length */
    u_char flags:6;          /* flags */
    u_char reserved_2:2;
    #else
    u_char thl:4;
    u_char reserved_1:4;
    u_char reserved_2:2;
    u_char flag:6;
    #endif
    u_short  window;         /* 16 bits */
    u_short  checksum;       /* 16 bits */
    u_short  urgent_pointer; /* 16 bits */
}tcp_header_t;

/* udp header */
typedef struct udp_header {
    u_short src_port; /* 16 bits */
    u_short dst_port; /* 16 bits */
    u_short length; /* 16 bits */
    u_short checksum; /* acknowledge number (16 bits) */
}udp_header_t;


typedef struct app_proto_data_s {
    APP_PROTOCOL_E type;
    void *data;
}app_proto_data_t;

#pragma pack()


#define ETH_HEADER_LENGTH (sizeof(eth_header_t))
#define IP_HEADER_LENGTH (sizeof(ip_header_t))
#define TCP_HEADER_LENGTH (sizeof(tcp_header_t))
#define UDP_HEADER_LENGTH (sizeof(udp_header_t))

void eth_header_ntoh(eth_header_t *header);
void eth_header_print(eth_header_t *header);

void ip_header_ntoh(ip_header_t *header);
void ip_header_print(ip_header_t *header);
int contain_options(ip_header_t *header);

void tcp_header_ntoh(tcp_header_t *header);
void tcp_header_print(tcp_header_t *header);

void udp_header_ntoh(udp_header_t *header);
void udp_header_print(udp_header_t *header);



#endif // _SRC_PROTOCOL_PROTOCOL_H_