#ifndef _TPCAP_SRC_PROTOCOL_APP_POTO_H_
#define _TPCAP_SRC_PROTOCOL_APP_POTO_H_

typedef enum {
    APP_PROTO_NONE = 0,
    APP_PROTO_HTTP,
    APP_PROTO_MAX
}APP_PROTOCOL_E;

int tcp_app_proto_recognize(tcp_header_t *header, u_char *data, int len);

#endif // _TPCAP_SRC_PROTOCOL_APP_POTO_H_