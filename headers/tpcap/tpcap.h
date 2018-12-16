#ifndef _HEADERS_TPACP_H_
#define _HEADERS_TPACP_H_


//typedef struct tcp_packet {
//    ushort_t source_port;
//    ushort_t dest_port;
//    uint32_t seq;
//    uint32_t ack;
//    uchar_t header_len:4;
//    uchar_t resv:4;
//    struct flag {
//        uchar_t cwr:1;
//        uchar_t ece:1;
//        uchar_t urg:1;
//        uchar_t ack:1;
//        uchar_t rsh:1;
//        uchar_t rst:1;
//        uchar_t syn:1;
//        uchar_t fin:1;
//    };
//    ushort_t windows_size;
//    ushort_t check_sum;
//    ushort_t urgent_pointer;
//}tcp_packet_t;

int tpcap_create(void **handle);
int tpcap_delete(void *handle);
int tpcap_load(void *handle, const char *path);
void tpcap_print(void *handle);



#endif /* end of _HEADERS_TPACP_H_ */
