#include <stdio.h>
#include <arpa/inet.h>
#include "src/pcap/pcap_parser.h"




int main()
{
    int count = 0;
    pcap_t *pcap;

    pcap_init(&pcap);
    count = pcap_parser(pcap, "test.pcap");
    printf("packet count: %d\n", count);
    pcap_analyse(pcap);
    printf("eth_packet_count : %d\n"
           "ip_packet_count  : %d\n"
           "tcp_packet_count  : %d\n",
             pcap->eth_packet_count,
             pcap->ip_packet_count,
             pcap->tcp_packet_count);
    //pcap_out(pcap);
    pcap_print_tcp(pcap);
    pcap_finish(pcap);
}
