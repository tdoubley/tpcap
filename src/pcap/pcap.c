#include "src/pcap/pcap.h"

void file_header_print(pcap_file_header_t *header) {
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

void packet_header_print(pcap_packet_header_t *header) {
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


