/*Header containing structure of network packet headers and payloads*/
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
    #define IP_DF 0x4000      //DF 'dont fragment' flag
    #define IP_MF 0x2000      //MF 'more fragment' flag
    #define IP_OFFMASK 0x1fff //Mask for fragmenting bits
    u_int8_t    ttl;          //Time to live
    u_int8_t    protocol;     //Protocol
    u_int16_t   sum;          //Checksum
    struct in_addr src, dst;  //Source and destination address
};



struct inv6_addr {
    unsigned char bytes[16]; //*< 128 bit IP6 address
};


struct ipv6_hdr {
    union {
        struct hdrctl {
            unsigned int   un1_flow; //Version, class, flow
            unsigned short un1_plen; //Payload length
            unsigned char  un1_nxt;  //Next header
            unsigned char  un1_hlim; //Hop limit
        } un1;
        unsigned char un2_vfc; //4 bits version, 4 bits class
    } ctlun;
    struct inv6_addr src, dst; //Source and destination address
};




//ARP header
struct arp_hdr {
    u_int16_t htype; //Hardware type
    u_int16_t ptype; //protocol type
    u_char    hlen;  //Hardware address length
    u_char    plen;  //Protocol address length
    u_int16_t op;    //Operation code
    #define ARP_REQUEST 1
    #define ARP_REPLY 2
    u_char sha[6];   //Sender hardware address
    u_char spa[4];   //Sender IP address
    u_char tha[6];   //Target hardware address
    u_char tpa[4];   //Target IP address
};

//TCP header
struct tcp_hdr {
    u_short sport;  //Source port
    u_short dport;  //Destination port
    u_int   seq;    //Sequence number
    u_int   ack;    //Acknowledge number
    u_char  offx2;  //Data offset
    #define OFF(tcp)    (((tcp)->offx2 & 0xf0) >> 4)
    u_char  flags;
    #define TCP_FIN  0x01 //No more data from sender
    #define TCP_SYN  0x02 //Synchronise sequence number
    #define TCP_RST  0x04 //Reset the connection
    #define TCP_PUSH 0x08 //Push function
    #define TCP_ACK  0x10 //Acknowledge field significant
    #define TCP_URG  0x20 //Urgent pointer field significant
    #define TCP_ECE  0x40 //ECN echo
    #define TCP_CWR  0x80 //Congestion window reduced
    #define TCP_FLAGS    (TCP_FIN|TCP_SYN|TCP_RST|TCP_ACK|TCP_URG|TCP_ECE|TCP_CWR)
    u_short win;  //Window size
    u_short sum;  //Checksum
    u_short urp;  //Urgent pointer
};

//UDP header
struct udp_hdr {
    u_short sport; //source port
    u_short dport; //destination port
    u_short ulen;  //length
    u_short sum;   //checksum
};

struct dns_hdr {
        unsigned id:16; //Transaction ID
#if (defined BYTE_ORDER && BYTE_ORDER == BIG_ENDIAN) || (defined __sun && defined _BIG_ENDIAN)
        unsigned qr:1;    //Query/ Response
        unsigned opcode:4;//Operation code.
        unsigned aa:1;    //Authoritative answer flag.
        unsigned tc:1;    //Truncation flag
        unsigned rd:1;    //Recursion desired
        unsigned ra:1;i   //Recursion available
        unsigned unused:3;//Reserved bits
        unsigned rcode:4; //Query response code
#else
        unsigned rd:1;    //Recursion desired
        unsigned tc:1;    //Truncation flag
        unsigned aa:1;    //Authoritative answer
        unsigned opcode:4;//Operation code
        unsigned qr:1;    //Query/ Response
        unsigned rcode:4; //Query response code
        unsigned unused:3;//Reserved bits
        unsigned ra:1;    //Recursion available
#endif
        unsigned qdcount:16;//Question count
        unsigned ancount:16;//Answer record count
        unsigned nscount:16;//Name Server authority record count
        unsigned arcount:16;//Additional Record count
};

