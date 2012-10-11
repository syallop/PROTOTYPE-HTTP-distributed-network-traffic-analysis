//These includes really shouldn't be here..
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <json/json.h>

/* For reference, headers are layered:PCAP:Datalink:Network:Transport:...
 * E.G:
 *     PCAP:      size arrival time ...
 *     Datalink:  ethernet(srcMAC dstMAC)/ ...
 *     Network:   IPv4(srcIP, dstIP, ...)/ IPv6(...)
 *     Transport: TCP(...)/ UDP(...)
 */

void getJsonPacket(const struct pcap_pkthdr* pcapHeader, const u_char* pcapPayload,
                   int count, json_object* jsonPacket);


//========Datalink layer========================//
void getJsonEthernet(const u_char* ethernetPacket, json_object* jsonEthernet);
//==============================================//


//========Network layer==============//
void getJsonIP(const u_char* ipPacket, json_object* jsonIP);

void getJsonIPv6(const u_char* ipv6Packet, json_object* jsonIPv6);

void getJsonARP(const u_char* arpPacket, json_object* jsonARP);
//==================================//


//========Transport layer=============//
void getJsonTCP(const u_char* tcp, json_object* jsonTCP);

void getJsonUDP(const u_char* udp, json_object* jsonUDP);
//===================================//




//========Packet headers=======================================//
//Ethernet header
struct ethernet_hdr {
    u_char  ether_dhost[ETHER_ADDR_LEN];
    u_char  ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};

//IP header without options.
struct ip_hdr {
    u_int8_t vhl;             //Header length, version
    #define IP_V(ip) (((ip)->vhl & 0xf0) >> 4)
    #define IP_HL(ip) ((ip)->vhl & 0x0f)
    u_int8_t    tos;          //'Type of service'/DSCP
    u_int16_t   len;          //Total length
    u_int16_t   id;           //Identification
    u_int16_t   off;          //Fragment offset
    #define IP_DF 0x4000         //DF 'dont fragment' flag
    #define IP_MF 0x2000         //MF 'more fragment' flag
    #define IP_OFFMASK 0x1fff    //Mask for fragmenting bits
    u_int8_t    ttl;          //Time to live
    u_int8_t    protocol;            //Protocol
    u_int16_t   sum;          //Checksum
    struct in_addr src, dst;//Source and destination address
};

//TCP header
struct tcp_hdr {
    u_short tcp_sport;
    u_short tcp_dport;
    u_int   tcp_seq;
    u_int   tcp_ack;
    u_char  tcp_offx2;
    #define TCP_OFF(tcp)    (((tcp)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
    #define TCP_FIN 0x01
    #define TCP_SYN 0x02
    #define TCP_RST 0x04
    #define TCP_PUSH 0x08
    #define TCP_ACK 0x10
    #define TCP_URG 0x20
    #define TCP_ECE 0x40
    #define TCP_CWR 0x80
    #define TCP_FLAGS    (TCP_FIN|TCP_SYN|TCP_RST|TCP_ACK|TCP_URG|TCP_ECE|TCP_CWR)
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

//UDP header
struct udp_hdr {
    u_short udp_sport; //source port
    u_short udp_dport; //destination port
    u_short udp_ulen;  //length
    u_short udp_sum;   //checksum
};

int compileAndSetFilter(pcap_t* handle, char filter[], int optimise, bpf_u_int32 netmask);
