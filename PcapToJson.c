#include "PcapToJson.h"
/* Compile with: gcc PcapToJson.c -lpcap -ljson -o PcapToJson */

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
    json_object_object_add(jsonPacket,"number",   json_object_new_int(count));
    json_object_object_add(jsonPacket,"size",     json_object_new_int(pcapHeader->len));
    json_object_object_add(jsonPacket,"seconds",  json_object_new_int(pcapHeader->ts.tv_sec));
    json_object_object_add(jsonPacket,"useconds", json_object_new_int(pcapHeader->ts.tv_usec));

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

    json_object *type, *macSrc, *macDst; //Attributes of jsonEthernet

    type = json_object_new_string("ethernet");
    json_object_object_add(jsonEthernet, "type", type);

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
            //getJsonIPv6(ethernetPayload, jsonNetwork);
            break;
        case ETHERTYPE_ARP:
            //getJsonARP(ethernetPayload, jsonNetwork);
            break;
    }
    json_object_object_add(jsonEthernet, "network", jsonNetwork);

    return;
}

/* Given an IP packet, construct a Json representation in jsonIP */
void getJsonIP(const u_char* ipPacket, //An entire IP packet
               json_object* jsonIP) {  //Result

    //Get a pointer to the IP packets header and its payload.
    const struct ip_hdr* ipHeader = (struct ip_hdr* ) ipPacket;
    //const u_char* ipPayload = ipHeader;//+lengthofipheader;

    //NOTE: Proceed assuming the IP packet is not malformed
    json_object_object_add(jsonIP, "type", json_object_new_string("IP"));

    //Add the source and destination IP address
    json_object_object_add(jsonIP, "ipSrc", json_object_new_string(inet_ntoa(ipHeader->src)));
    json_object_object_add(jsonIP, "ipDst", json_object_new_string(inet_ntoa(ipHeader->src)));

    //Add the lower transport layer.
    json_object *jsonTransport = json_object_new_object();
    switch (ipHeader->protocol) {
        case 0x06:
            //getJsonTCP(ipPayload, jsonTransport);
            break;
        case 0x11:
            //getJsonUDP(ipPayload, jsonTransport);
            break;
    }
    json_object_object_add(jsonIP, "transport", jsonTransport);
    return;
}

/* TODO below function implementations*/
void getJsonIPv6(const u_char* ipv6Packet, json_object* jsonIPv6);
void getJsonARP(const u_char* arpPacket, json_object* jsonARP);

void getJsonTCP(const u_char* tcpPacket, json_object* jsonTCP);
void getJsonUDP(const u_char* udpPacket, json_object* jsonUDP);


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
