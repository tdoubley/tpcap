#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

/* etnernet */
#define  ETH_P_IP 0x0800    //IP协议
#define  ETH_P_ARP 0x0806   //地址解析协议(Address Resolution Protocol)
#define  ETH_P_RARP 0x8035  //返向地址解析协议(Reverse Address Resolution Protocol)
#define  ETH_P_IPV6 0x86DD  //IPV6协议


/* IP */
#define IP_P_ICMP   1
#define IP_P_IGMP   3
#define IP_P_TCP    6
#define IP_P_EGP    8
#define IP_P_IGP    9
#define IP_P_UDP    17
#define IP_P_IPv6   41
#define IP_P_OSPF   89


#endif // _PROTOCOL_H_