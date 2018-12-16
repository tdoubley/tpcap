#include <stdio.h>
#include <arpa/inet.h>
#include "tpcap/tpcap.h"




int main()
{
    int count = 0;
    void *pcap;

    tpcap_create(&pcap);
    count = tpcap_load(pcap, "test.pcap");
    printf("packet count: %d\n", count);
    //tpcap_print(pcap);
    tpcap_delete(pcap);
}
