#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "src/debug.h"

#include "tpcap/tpcap.h"

#include "src/parser.h"
#include "src/protocol/app_proto.h"
#include "src/utils/utlist.h"


static void file_header_print(pcap_file_header_t *header) {
    printf("==========pcap file Header===========\n"
           "Magic: %d\n"
           "Version major: %d\n"
           "Version minor : %d\n"
           "This zone : %d\n"
           "Sigfigs : %d\n"
           "Snaplen : %d\n"
           "Linktype : %d\n",
           header->magic,
           header->version_major,
           header->version_minor,
           header->thiszone,
           header->sigfigs,
           header->snaplen,
           header->linktype);

    return;
}

static void packet_header_print(pcap_packet_header_t *header) {
    u_char timestamp[50] = {0};
    sprintf(timestamp, "%d.%d", header->ts.timestamp_s, header->ts.timestamp_ms);
    printf("==========pcap packet Header===========\n"
           "Timestamp: %s\n"
           "Capture length: %d\n"
           "Length : %d\n",
           timestamp,
           header->capture_len,
           header->len);

    return;
}

int tpcap_create(pcap_t **handle) {
    if (handle == NULL) {
        return -1;
    }
    int ret = 0;

    pcap_t *pcap = (pcap_t *)malloc(sizeof(pcap_t));
    if (pcap == NULL) {
        return -1;
    }
    memset(pcap, 0, sizeof(pcap_t));
    *handle = pcap;

    ret = parser_init();

    DEBUG_PRINT("%s", "pcap create\n");

    return ret;
}

int tpcap_destory(pcap_t *handle) {
    if (handle == NULL) {
        return -1;
    }

    pcap_t *pcap = (pcap_t *)handle;
    parser_free(pcap->packets);

    DEBUG_PRINT("%s", "pcap finished\n");

    return 0;
}

int tpcap_load(pcap_t *handle, const char *path) {
    if (handle == NULL || path == NULL) {
        return -1;
    }

    pcap_t *pcap = (pcap_t *)handle;

    parser_load_file(pcap, path);

    parser_analyse(pcap);

    return 0;
}


void tpcap_dump(pcap_t *handle) {
    if (handle == NULL) {
        return;
    }

    pcap_t *pcap = (pcap_t *)handle;

    file_header_print(&pcap->file_header);

    pcap_packet_node_t *head = pcap->packets;
    pcap_packet_node_t *node = NULL;

    LL_FOREACH(head, node) {
         packet_header_print(&node->header);
    }

    return;
}

