#ifndef _TPCAP_SRC_PROTOCOL_APP_POTO_H_
#define _TPCAP_SRC_PROTOCOL_APP_POTO_H_


typedef void * (*app_protocl_parser_init)(void);
typedef int (*app_protocl_parser_parser)(u_char*, uint32_t);
typedef int (*app_protocl_parser_deinit)(void);

typedef struct app_protocol_parser_s {
    APP_PROTOCOL_E type;
    app_protocl_parser_init init;
    app_protocl_parser_deinit deinit;
    app_protocl_parser_parser parser;
}app_protocol_parser_t;


int tcp_app_proto_recognize(tcp_header_t *header, u_char *data, int len);

#endif // _TPCAP_SRC_PROTOCOL_APP_POTO_H_