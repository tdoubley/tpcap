#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "src/debug.h"
#include "src/protocol/protocol.h"
#include "tpcap/tpcap.h"
#include "src/pcap/pcap_parser.h"

int tpcap_create(void **handle) {
    if (handle == NULL) {
        return -1;
    }

    pcap_t *pcap = (pcap_t *)malloc(sizeof(pcap_t));
    if (pcap == NULL) {
        return -1;
    }
    memset(pcap, 0, sizeof(pcap_t));
    *handle = pcap;

    DEBUG_PRINT("%s", "pcap create\n");

    return 0;
}

int tpcap_delete(void *handle) {
    if (handle == NULL) {
        return -1;
    }

    pcap_t *pcap = (pcap_t *)handle;
    pcap_free(pcap->packets);

    DEBUG_PRINT("%s", "pcap finished\n");

    return 0;
}

int tpcap_load(void *handle, const char *path) {
    if (handle == NULL || path == NULL) {
        return -1;
    }

    pcap_t *pcap = (pcap_t *)handle;

    return pcap_parser(pcap, path);
}

void tpcap_print(void *handle) {
    if (handle == NULL) {
        return;
    }

    pcap_t *pcap = (pcap_t *)handle;
    pcap_print(pcap);

    return;
}




