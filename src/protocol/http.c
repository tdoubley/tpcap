#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "tpcap/protocol.h"
#include "src/protocol/app_proto.h"
#include "src/protocol/http.h"
#include "http-parser/http_parser.h"


static int on_message_begin(http_parser* p) {
    printf("===========http parsing start===========\n");

    return 0;
}

static int on_headers_complete(http_parser* p) {
    return 0;
}
static int on_message_complete(http_parser* p) {
    printf("===========http parsing end===========\n");

    return 0;
}

static int on_header_field(http_parser* p, const char *at, size_t length) {
    printf("%.*s\n", length, at);

    return 0;
}

static int on_header_value(http_parser* p, const char *at, size_t length) {
    printf("%.*s\n", length, at);

    return 0;
}


static int on_url(http_parser* p, const char *at, size_t length) {
    printf("%.*s\n", length, at);

    return 0;
}

static int on_status(http_parser* p, const char *at, size_t length) {
    printf("%.*s\n", length, at);

    return 0;
}

static int on_body(http_parser* p, const char *at, size_t length) {
    printf("%.*s\n", length, at);

    return 0;
}

static http_parser_settings settings = {
  .on_message_begin = on_message_begin,
  .on_headers_complete = on_headers_complete,
  .on_message_complete = on_message_complete,
  .on_header_field = on_header_field,
  .on_header_value = on_header_value,
  .on_url = on_url,
  .on_status = on_status,
  .on_body = on_body
};

int do_http_parser(u_char *data, uint32_t len)
{
    struct http_parser parser;
    size_t parsed;

    http_parser_init(&parser, HTTP_BOTH);
    parsed = http_parser_execute(&parser, &settings, data, len);
    if (parsed != len) {
        return -1;
    } else {
        return parsed;
    }
}

static void * app_http_parser_init(void)
{
    http_t *p = malloc(sizeof(http_t));
    memset(p, 0, sizeof(http_t));

    return p;
}

static int app_http_parser_deinit(void *http)
{
    return 0;
}


int http_parser_register(app_protocol_parser_t *parser)
{
    if (parser == NULL) {
        return -1;
    }

    parser->type = APP_PROTO_HTTP;
    parser->init = NULL;
    parser->parser = do_http_parser;
    parser->deinit = NULL;
}


