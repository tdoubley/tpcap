#ifndef _SRC_PROTOCOL_HTTP_H_
#define _SRC_PROTOCOL_HTTP_H_


typedef struct str {
    u_char *data;
    unsigned len;
}str_t;

typedef struct http_header {
    str_t name;
    str_t value;
    struct http_header *next;
}http_header_t;

/* HTTP */
typedef struct http {
    str_t uri;
    http_header_t *headers;
    str_t body;
}http_t;

int do_http_parser(u_char *data, uint32_t len);


#endif // _SRC_PROTOCOL_HTTP_H_
