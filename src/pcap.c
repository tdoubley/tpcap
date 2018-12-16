//
//  pcap.c
//  pcaptest
//
//  Created by zc on 12-1-24.
//  Copyright 2012年 __MyCompanyName__. All rights reserved.
//
 
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "tpcap/tpcap.h"
#include "utils/utlist.h"


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


int pcap_create(void **handle) {
    if (handle == NULL) {
        return -1;
    }

    pcap_t *pcap = (pcap_t *)malloc(sizeof(pcap_t));
    if (pcap == NULL) {
        return -1;
    }
    memset(pcap, 0, sizeof(pcap_t));
    *handle = pcap;

    return 0;
}

int pcap_delete(void *pcap) {
    if (pcap == NULL) {
        return -1;
    }

    pcap_free(((pcap_t *)pcap)->packets);

    return 0;
}

int pcap_load(void *handle, const char *path) {
    FILE *fp = fopen(path, "rw");
    if (fp == NULL) {
        return -1;
    }

    pcap_t *pcap = (pcap_t *)handle;

    /* 读取文件头 */
    fread(&pcap->file_header, sizeof(pcap_file_header_t), 1, fp);
    pcap_file_header_out(&pcap->file_header);

    int count = 0;
    int failed_count = 0;
    int read_count = 0;
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
        uchar_t *buf = (uchar_t *)malloc(buf_len);
        read_count = fread(buf, 1, buf_len, fp);
        if (read_count != buf_len) {
            pcap_free_node(packet_node);
            free(buf);
            failed_count++;
            break;
        } else {
            packet_node->data = buf;
        }

        pcap_packet_header_out(&packet_node->header);

        LL_PREPEND(pcap->packets, packet_node);

        count++;
    }

    return count;
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

    printf("=====================\n"
       "ts.timestamp_s:%u\n"
       "ts.timestamp_ms:%u\n"
       "capture_len:%u\n"
       "len:%d\n"
       "=====================\n",
       node->header.ts.timestamp_s,
       node->header.ts.timestamp_ms,
       node->header.capture_len,
       node->header.len);
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



