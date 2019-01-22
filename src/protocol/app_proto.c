#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "src/protocol/protocol.h"

#include "src/protocol/app_proto.h"

int tcp_app_proto_recognize(tcp_header_t *header, u_char *data, int len)
{
    if ((len >= 3 && strncmp(data, "GET", 3) == 0)
        || (len >= 4 && strncmp(data, "POST", 3) == 0)
        || (len >= 4 && strncmp(data, "HTTP", 3) == 0)) {
        int i;
        printf("------HTTP-------\n");
        for (i = 0; i < len; i++) {
            printf("%c", data[i]);
        }

        return APP_PROTO_HTTP;
     }

    return APP_PROTO_NONE;
}


