#include "PcapToJson.h"
/* Compile with: gcc PcapToJson.c -lpcap -ljson -o PcapToJson */

void inline add_to_object_new_string(json_object* root, char name[], char value[]) {
    json_object_object_add(root, name, json_object_new_string(value));
}
void inline add_to_object_new_int(json_object* root, char name[], int value) {
    json_object_object_add(root, name, json_object_new_int(value));
}
void inline add_to_object_new_boolean(json_object* root, char name[], int value) {
    json_object_object_add(root, name, json_object_new_boolean(value));
}


//Attempt to apply a bpf format filter to a pcap handle
int compileAndSetFilter(pcap_t* handle, //source of pcap data
                        char filter[],  //bpf filter string
                        int optimise,   //whether to optimise the program
                        bpf_u_int32 netmask) {
    struct bpf_program program;
    if(pcap_compile(handle, &program, filter, optimise, netmask) == -1) {
        fprintf(stderr, " Filter compilation failed: %s\n", pcap_geterr(handle));
        return 1;
    }
    if(pcap_setfilter(handle, &program) == -1) {
        fprintf(stderr, " Setting filter failed: %s\n", pcap_geterr(handle));
        return 1;
    }
    return 0;
}

/* Given a PCAP packet and its header, construct a Json representation in jsonPacket */
void getJsonPacket(const struct pcap_pkthdr* pcapHeader,  //PCAP packet header
                   const u_char* pcapPayload,             //PCAP packet contents
                   int count,                             //Number to label jsonPacket as
                   json_object* jsonPacket) {             //Result

    //Add basic attributes
    add_to_object_new_int(jsonPacket, "number", count);
    add_to_object_new_int(jsonPacket, "size", pcapHeader->len);
    add_to_object_new_int(jsonPacket, "seconds", pcapHeader->ts.tv_sec);
    add_to_object_new_int(jsonPacket, "useconds", pcapHeader->ts.tv_usec);

    //TODO switch over the possible datalink layer types. Currently assumes type is ethernet.
    //Add the datalink layer
    json_object *jsonDatalink = json_object_new_object();
    switch (0) {
        case 0: getJsonEthernet(pcapPayload, jsonDatalink);
    }
    json_object_object_add(jsonPacket, "datalink", jsonDatalink);
    return;
}

/* Given an ethernet packet, construct a Json representation in jsonEthernet */
void getJsonEthernet(const u_char* ethernetPacket, //An entire ethernet packet
                     json_object* jsonEthernet) {  //Result

    char tmpstr[20];

    //Get a pointer to the ethernet packets header and its payload
    struct ether_header* ethernetHeader = (struct ether_header* ) ethernetPacket;
    const u_char* ethernetPayload = (ethernetPacket + sizeof(struct ether_header));

    json_object *macSrc, *macDst; //Attributes of jsonEthernet
    add_to_object_new_string(jsonEthernet, "type","ethernet");

    //Set the source and destination MAC addresses
    sprintf(tmpstr, "%02x:%02x:%02x:%02x:%02x:%02x",
                 (unsigned)ethernetHeader->ether_shost[0],
                 (unsigned)ethernetHeader->ether_shost[1],
                 (unsigned)ethernetHeader->ether_shost[2],
                 (unsigned)ethernetHeader->ether_shost[3],
                 (unsigned)ethernetHeader->ether_shost[4],
                 (unsigned)ethernetHeader->ether_shost[5]);
    macSrc = json_object_new_string(tmpstr);
    json_object_object_add(jsonEthernet, "macSrc", macSrc);

    sprintf(tmpstr, "%02x:%02x:%02x:%02x:%02x:%02x",
                 (unsigned)ethernetHeader->ether_dhost[0],
                 (unsigned)ethernetHeader->ether_dhost[1],
                 (unsigned)ethernetHeader->ether_dhost[2],
                 (unsigned)ethernetHeader->ether_dhost[3],
                 (unsigned)ethernetHeader->ether_dhost[4],
                 (unsigned)ethernetHeader->ether_dhost[5]);
    macDst  = json_object_new_string(tmpstr);
    json_object_object_add(jsonEthernet, "dst", macDst);

    //Add the lower network layer.
    json_object *jsonNetwork = json_object_new_object();
    switch (ntohs(ethernetHeader->ether_type)) {
        case ETHERTYPE_IP:
            getJsonIP(ethernetPayload, jsonNetwork);
            break;
        case ETHERTYPE_IPV6:
            getJsonIPv6(ethernetPayload, jsonNetwork);
            break;
        case ETHERTYPE_ARP:
            getJsonARP(ethernetPayload, jsonNetwork);
            break;
        default:
            add_to_object_new_string(jsonNetwork,"type","UNKNOWN");
    }
    json_object_object_add(jsonEthernet, "network", jsonNetwork);

    return;
}

/* Given an IP packet, construct a Json representation in jsonIP */
void getJsonIP(const u_char* ipPacket, //An entire IP packet
               json_object* jsonIP) {  //Result

    //Get a pointer to the IP packets header and its payload.
    const struct ip_hdr* ipHeader = (struct ip_hdr* ) ipPacket;
    const u_char* ipPayload = (ipPacket + sizeof(struct ip_hdr));

    //Validate packet
    if(IP_HL(ipHeader) < 5) {
        fprintf(stderr,"IP header too small.\n");
        return;
    }
    add_to_object_new_string(jsonIP, "type", "IP");

    //Add the source and destination IP address
    add_to_object_new_string(jsonIP, "ipSrc", inet_ntoa(ipHeader->src));
    add_to_object_new_string(jsonIP, "ipDst", inet_ntoa(ipHeader->dst));

    //Add some other data..
    add_to_object_new_int(jsonIP, "total length", ntohs(ipHeader->len));
    add_to_object_new_int(jsonIP, "header length", IP_HL(ipHeader));

    //Add the lower transport layer.
    json_object *jsonTransport = json_object_new_object();
    switch (ipHeader->protocol) {
        case 0x06:
            getJsonTCP(ipPayload, jsonTransport);
            break;
        case 0x11:
            getJsonUDP(ipPayload, jsonTransport);
            break;
        default:
            add_to_object_new_string(jsonTransport,"type","UNKNOWN");
            break;
    }
    json_object_object_add(jsonIP, "transport", jsonTransport);
    return;
}

void getJsonIPv6(const u_char* ipv6Packet, json_object* jsonIPv6) {
    //Get pointer to the upv6 packet and its header
    const struct ipv6_hdr* ipv6Header = (struct ipv6_hdr* ) ipv6Packet;
    const u_char* ipv6Payload = (ipv6Packet + sizeof(struct ipv6_hdr));

    char tmpStr[40];

    //Add source and destination IPv6 address
    add_to_object_new_string(jsonIPv6, "type","IPv6");

    sprintf(tmpStr, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            (int)ipv6Header->src.bytes[0], (int)ipv6Header->src.bytes[1],
            (int)ipv6Header->src.bytes[2], (int)ipv6Header->src.bytes[3],
            (int)ipv6Header->src.bytes[4], (int)ipv6Header->src.bytes[5],
            (int)ipv6Header->src.bytes[6], (int)ipv6Header->src.bytes[7],
            (int)ipv6Header->src.bytes[8], (int)ipv6Header->src.bytes[9],
            (int)ipv6Header->src.bytes[10], (int)ipv6Header->src.bytes[11],
            (int)ipv6Header->src.bytes[12], (int)ipv6Header->src.bytes[13],
            (int)ipv6Header->src.bytes[14], (int)ipv6Header->src.bytes[15]);
    add_to_object_new_string(jsonIPv6, "ipSrc", tmpStr);

    sprintf(tmpStr, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            (int)ipv6Header->dst.bytes[0], (int)ipv6Header->dst.bytes[1],
            (int)ipv6Header->dst.bytes[2], (int)ipv6Header->dst.bytes[3],
            (int)ipv6Header->dst.bytes[4], (int)ipv6Header->dst.bytes[5],
            (int)ipv6Header->dst.bytes[6], (int)ipv6Header->dst.bytes[7],
            (int)ipv6Header->dst.bytes[8], (int)ipv6Header->dst.bytes[9],
            (int)ipv6Header->dst.bytes[10], (int)ipv6Header->dst.bytes[11],
            (int)ipv6Header->dst.bytes[12], (int)ipv6Header->dst.bytes[13],
            (int)ipv6Header->dst.bytes[14], (int)ipv6Header->dst.bytes[15]);
    add_to_object_new_string(jsonIPv6, "ipDst", tmpStr);

    //Add the lower transport layer.
    json_object *jsonTransport = json_object_new_object();
    switch (ipv6Header->ctlun.un1.un1_nxt) {
        case 0x06:
            getJsonTCP(ipv6Payload, jsonTransport);
            break;
        case 0x11:
            getJsonUDP(ipv6Payload, jsonTransport);
            break;
        default:
            add_to_object_new_string(jsonTransport,"type","UNKNOWN");
            break;
    }
    json_object_object_add(jsonIPv6, "transport", jsonTransport);


}
void getJsonARP(const u_char* arpPacket, json_object* jsonARP) {
    const struct arp_hdr* arpHeader = (struct arp_hdr* ) arpPacket;

    char tmpip[16];
    char tmpmac[17];

    add_to_object_new_string(jsonARP, "type", "ARP");
    add_to_object_new_int(jsonARP,    "hardware",   ntohs(arpHeader->htype));
    add_to_object_new_int(jsonARP,    "protocol",   ntohs(arpHeader->ptype));
    add_to_object_new_string(jsonARP,  "operation", (ntohs(arpHeader->op)== ARP_REQUEST)? "REQ":"REP");

    //Add sender ip and mac
    sprintf(tmpip, "%d.%d.%d.%d",
                 arpHeader->spa[0],
                 arpHeader->spa[1],
                 arpHeader->spa[2],
                 arpHeader->spa[3]);
    add_to_object_new_string(jsonARP, "sender ip", tmpip);

    sprintf(tmpmac, "%02x:%02x:%02x:%02x:%02x:%02x",
                arpHeader->sha[0],
                arpHeader->sha[1],
                arpHeader->sha[2],
                arpHeader->sha[3],
                arpHeader->sha[4],
                arpHeader->sha[5]);
    add_to_object_new_string(jsonARP, "sender mac", tmpmac);

    //Add target ip and mac
    sprintf(tmpip, "%d.%d.%d.%d",
                 arpHeader->tpa[0],
                 arpHeader->tpa[1],
                 arpHeader->tpa[2],
                 arpHeader->tpa[3]);
    add_to_object_new_string(jsonARP, "target ip", tmpip);

    sprintf(tmpmac, "%02x:%02x:%02x:%02x:%02x:%02x",
                arpHeader->tha[0],
                arpHeader->tha[1],
                arpHeader->tha[2],
                arpHeader->tha[3],
                arpHeader->tha[4],
                arpHeader->tha[5]);
    add_to_object_new_string(jsonARP, "target mac", tmpmac);

}

void getJsonTCP(const u_char* tcpPacket, json_object* jsonTCP) {
    const struct tcp_hdr* tcpHeader = (struct tcp_hdr* ) tcpPacket;

    add_to_object_new_string(jsonTCP, "type",    "TCP");
    add_to_object_new_int(jsonTCP,    "srcPort", ntohs(tcpHeader->sport));
    add_to_object_new_int(jsonTCP,    "dstPort", ntohs(tcpHeader->dport));

}
void getJsonUDP(const u_char* udpPacket, json_object* jsonUDP) {
    const struct udp_hdr* udpHeader = (struct udp_hdr* ) udpPacket;
    const u_char* udpPayload = (udpPacket + sizeof(struct udp_hdr));

    add_to_object_new_string(jsonUDP,"type","UDP");
    add_to_object_new_int(jsonUDP, "srcPort", ntohs(udpHeader->sport));
    add_to_object_new_int(jsonUDP, "dstPort", ntohs(udpHeader->dport));
    add_to_object_new_int(jsonUDP, "length", ntohs(udpHeader->ulen));

    /*Below case statements will be inefficient/ buggy*/
    json_object *jsonApplication = json_object_new_object();
    switch(ntohs(udpHeader->dport)) {
        case 53:
            getJsonDNS(udpPayload, jsonApplication);
            break;
    }
    switch(ntohs(udpHeader->sport)) {
        case 53:
            getJsonDNS(udpPayload, jsonApplication);
            break;
    }
    json_object_object_add(jsonUDP, "application", jsonApplication);
}


void getJsonDNS(const u_char* dnsPacket, json_object* jsonDNS) {
    const struct dns_hdr* dnsHeader = (struct dns_hdr* ) dnsPacket;

    add_to_object_new_string(  jsonDNS, "type",        "DNS"                 );
    add_to_object_new_int(     jsonDNS, "id",          ntohs(dnsHeader->id) );
    add_to_object_new_boolean( jsonDNS, "response",    dnsHeader->qr         );
    add_to_object_new_int(     jsonDNS, "opcode",      dnsHeader->opcode     );
    add_to_object_new_boolean( jsonDNS, "authorative", dnsHeader->aa         );
    add_to_object_new_boolean( jsonDNS, "truncated",   dnsHeader->tc         );
    add_to_object_new_boolean( jsonDNS, "rec-desired", dnsHeader->rd         );
    add_to_object_new_boolean( jsonDNS, "rec-allowed", dnsHeader->ra         );
    add_to_object_new_int(     jsonDNS, "rcode",       dnsHeader->rcode      );

    add_to_object_new_int(jsonDNS, "questions", ntohs(dnsHeader->qdcount));
    add_to_object_new_int(jsonDNS, "answers",   ntohs(dnsHeader->ancount));
    add_to_object_new_int(jsonDNS, "authrecords", ntohs(dnsHeader->nscount));
    add_to_object_new_int(jsonDNS, "additional-records", ntohs(dnsHeader->arcount));
}

//Print to stdout a Json representation of a packet
void writeJsonPacket(const struct pcap_pkthdr* pcapHeader, const u_char* pcapPayload, //PCAP header and payload
                     int count) {                                                     //Number to label packet as being
    json_object* jsonPacket = json_object_new_object();
    getJsonPacket(pcapHeader, pcapPayload, count, jsonPacket);
    printf("%s\n\n",json_object_to_json_string(jsonPacket));
    return;
}

//Callback function to be used with pcap_loop/ pcap_dispatch to process a single packet.
void jsonPacketCallback (u_char* extraArgs,                                                 //Space to pass additional arguments to callback
                         const struct pcap_pkthdr* pcapHeader, const u_char* pcapPayload) { //Packets header and payload
    //Print numbered Json representation of all packets
    static int count = 1;
    writeJsonPacket(pcapHeader, pcapPayload, count);
    count++;
    return;
}

int main(int argc, char *argv[]) {
    pcap_t* handle;                    //Handle to a PCAP source
    char errbuf[PCAP_ERRBUF_SIZE];     //Buffer for PCAP errors
    char filter[] = "";                //Filter to apply to PCAP source
    int optimise = 1;                  //Whether to optimise the filter
    bpf_u_int32 netmask = 0xFFFFFF00;
    char inputfile[] = "capture.pcap";

    //Open a handle to a pcap format file
    handle = pcap_open_offline(inputfile, errbuf);
    if(handle == NULL) {
        fprintf(stderr, " Couldn't open file for capture: %s\n", errbuf);
        return 1;
    }

    //Attempt to apply the filter
    if (compileAndSetFilter(handle, filter, optimise, netmask) != 0){return 1;}

    //Loop a callback function over each packet
    pcap_loop(handle, -1, jsonPacketCallback, NULL);

    pcap_close(handle);
    return 0;
}
