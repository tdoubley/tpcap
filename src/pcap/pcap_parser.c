#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


#include "debug.h"
#include "src/pcap/pcap_parser.h"
#include "src/utils/utlist.h"

int pcap_init(pcap_t **ppcap) {
    if (ppcap == NULL) {
        return -1;
    }

    pcap_t *pcap = (pcap_t *)malloc(sizeof(pcap_t));
    if (pcap == NULL) {
        return -1;
    }
    memset(pcap, 0, sizeof(pcap_t));
    *ppcap = pcap;

    DEBUG_PRINT("%s", "pcap initial\n");

    return 0;
}

int pcap_finish(pcap_t *pcap) {
    if (pcap == NULL) {
        return -1;
    }

    pcap_free(((pcap_t *)pcap)->packets);

    DEBUG_PRINT("%s", "pcap finished\n");

    return 0;
}

int pcap_parser(pcap_t *pcap, const char *path) {
    FILE *fp = fopen(path, "rw");
    if (fp == NULL) {
        return -1;
    }

    int packet_count = 0;
    int read_count = 0;

    /* 读取文件头 */
    read_count = fread(&pcap->file_header, sizeof(pcap_file_header_t), 1, fp);
    if (read_count <= 0) {
        return -1;
    }

    DEBUG_PRINT("pcap file header:"
                "=====================\n"
                "magic:0x%0x\n"
                "version_major:%u\n"
                "version_minor:%u\n"
                "thiszone:%d\n"
                "sigfigs:%u\n"
                "snaplen:%u\n"
                "linktype:%u\n"
                "=====================\n",
                pcap->file_header.magic,
                pcap->file_header.version_major,
                pcap->file_header.version_minor,
                pcap->file_header.thiszone,
                pcap->file_header.sigfigs,
                pcap->file_header.snaplen,
                pcap->file_header.linktype);

    while(1) {
        pcap_packet_node_t *packet_node = (pcap_packet_node_t *)malloc(sizeof(pcap_packet_node_t));
        if (packet_node == NULL) {
            break;
        }
        memset(packet_node, 0, sizeof(pcap_packet_node_t));

        /* 读取包头 */
        read_count = fread(&packet_node->header, sizeof(pcap_packet_header_t), 1, fp);
        if (read_count <= 0) {
            pcap_free_node(packet_node);
            break;
        }

        /* 读取包数据 */
        uint32_t buf_len = packet_node->header.capture_len;
        u_char *buf = (u_char *)malloc(buf_len);
        read_count = fread(buf, 1, buf_len, fp);
        if (read_count != buf_len) {
            pcap_free_node(packet_node);
            free(buf);
            break;
        } else {
            packet_node->data = buf;
        }

        packet_count++;

        LL_PREPEND(pcap->packets, packet_node);

        DEBUG_PRINT("packet %d header:"
            "=====================\n"
            "ts.timestamp_s:%u\n"
            "ts.timestamp_ms:%u\n"
            "capture_len:%u\n"
            "len:%d\n"
            "=====================\n",
            packet_count,
            packet_node->header.ts.timestamp_s,
            packet_node->header.ts.timestamp_ms,
            packet_node->header.capture_len,
            packet_node->header.len);
    }

    return packet_count;
}


void pcap_file_header_out(const pcap_file_header_t *pfh)
{
    if (pfh==NULL) {
        return;
    }

    printf("=====================\n"
           "magic:0x%0x\n"
           "version_major:%u\n"
           "version_minor:%u\n"
           "thiszone:%d\n"
           "sigfigs:%u\n"
           "snaplen:%u\n"
           "linktype:%u\n"
           "=====================\n",
           pfh->magic,
           pfh->version_major,
           pfh->version_minor,
           pfh->thiszone,
           pfh->sigfigs,
           pfh->snaplen,
           pfh->linktype);
}

void pcap_packet_header_out(const pcap_packet_header_t *ph) {
    if (ph==NULL) {
        return;
    }

    printf("=====================\n"
           "ts.timestamp_s:%u\n"
           "ts.timestamp_ms:%u\n"
           "capture_len:%u\n"
           "len:%d\n"
           "=====================\n",
           ph->ts.timestamp_s,
           ph->ts.timestamp_ms,
           ph->capture_len,
           ph->len);
}

void pcap_out(void *handle) {
    if (handle == NULL) {
        return;
    }

    pcap_t *pcap = (pcap_t *)handle;
    pcap_packet_node_t *head = pcap->packets;
    pcap_packet_node_t *node = NULL;

    LL_FOREACH(head, node) {
        pcap_packet_node_out(node);
    }
}

void pcap_packet_node_out(pcap_packet_node_t *node) {
    if (node == NULL) {
        return;
    }

    pcap_packet_header_out(&node->header);
}

void pcap_free_node(pcap_packet_node_t* packet_node) {
    if (packet_node == NULL) {
        return;
    }

    if (packet_node->data != NULL) {
        free(packet_node->data);
    }

    free(packet_node);
}

void pcap_free(pcap_packet_node_t* head) {
    pcap_packet_node_t *node = NULL;
    pcap_packet_node_t *tmp = NULL;
    LL_FOREACH_SAFE(head, node, tmp) {
        pcap_free_node(node);
    }
}
