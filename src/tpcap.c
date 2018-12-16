#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "tpcap/tpcap.h"
#include "src/pcap/pcap_parser.h"

int tpcap_create(void **handle) {
    if (handle == NULL) {
        return -1;
    }

    pcap_t *pcap;
    if (pcap_init(&pcap) == 0) {
        *handle = pcap;
        return 0;
    } else {
        return -1;
    }
}

int tpcap_delete(void *handle) {
    if (handle == NULL) {
        return -1;
    }

    pcap_t *pcap = (pcap_t *)handle;
    pcap_finish(pcap);

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
    pcap_out(pcap);

    return;
}




