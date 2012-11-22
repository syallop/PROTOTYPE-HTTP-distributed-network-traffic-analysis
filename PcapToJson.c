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

//Given a packet and its header, construct a Json representation in 'jpacket'
void getJsonPacketLayer(const struct pcap_pkthdr* header, const u_char* packet, //Entire packet header and contents
                        int count,                                              //Number to label packet with
                        json_object* jpacket) {                                 //Result
    json_object *number, *size, *seconds, *useconds, *datalink;

    //Define basic key-value pairs to add
    number   = json_object_new_int(count);
    size     = json_object_new_int(header->len);
    seconds  = json_object_new_int(header->ts.tv_sec);
    useconds = json_object_new_int(header->ts.tv_usec);

    //Define datalink object to add
    datalink = json_object_new_object();
    getJsonDatalinkLayer(header, packet, datalink);

    //Add them
    json_object_object_add(jpacket, "number",   number);
    json_object_object_add(jpacket, "size",     size);
    json_object_object_add(jpacket, "seconds",  seconds );
    json_object_object_add(jpacket, "useconds", useconds);
    json_object_object_add(jpacket, "datalink", datalink);

    return;
}

//Create a Json object representing the data link layer of a packet
void getJsonDatalinkLayer(const struct pcap_pkthdr* header, const u_char* packet, //Entire packet header and contents
                          json_object* datalink) {                                //To store result
    //Assume the datalink level header is ethernet..
    struct ether_header* ethheader = (struct ether_header* ) packet;
    getJsonEthernet(header, packet, ethheader, datalink);
}

//Create a Json object representing the network layer of a packet
void getJsonNetworkLayer(const struct pcap_pkthdr* header, const u_char* packet, //Entire packet header and contents
                         const struct ether_header* ethheader,                   //Ethernet packet header only
                         json_object* networkLayer) {                            //Result
    json_object *type;
    //Match against known network layer protocols and call corresponding
    //json creation functions.
    switch(ntohs(ethheader->ether_type)) {
        case ETHERTYPE_IP:
            type = json_object_new_string("IPv4");
            json_object_object_add(networkLayer, "type", type);
            getJsonIPv4(header, packet, networkLayer);
            break;
        case ETHERTYPE_IPV6:
            type = json_object_new_string("IPv6");
            json_object_object_add(networkLayer, "type", type);
            break;
        case ETHERTYPE_ARP:
            type = json_object_new_string("ARP");
            json_object_object_add(networkLayer, "type", type);
            break;
        default:
            type = json_object_new_string("UNKNOWN");
            json_object_object_add(networkLayer, "type", type);
            break;
    }
    return;
}

//TODO implement this correctly...
//Create a Json object representing the transport layer of a packet
void getJsonTransportLayer(const struct pcap_pkthdr* header, const u_char* packet,
                           json_object* transportLayer) {
    json_object *type, *dst, *src;

    type = json_object_new_string("UDP");//confusing test values
    dst  = json_object_new_string("80");
    src  = json_object_new_string("8888");

    json_object_object_add(transportLayer, "type", type);
    json_object_object_add(transportLayer, "dst", dst);
    json_object_object_add(transportLayer, "src", src);

    //switch(transporttype)
    //case udp:
    //case tcp:
    return;
}



//Create a Json object representing an ethernet packet
void getJsonEthernet(const struct pcap_pkthdr* header, const u_char* packet, //Entire packet header and contents
                     const struct ether_header* ethheader,                   //Ethernet packet header only
                     json_object* ethernet) {                                //Result
    json_object *type, *src, *dst, *networklayer;
    char strsrc[20];
    char strdst[20];

    //Type of packet header is ethernet by assumption that this function has been called on an
    //ethernet packet header
    type = json_object_new_string("ethernet");
    json_object_object_add(ethernet, "type", type);

    //Set the source and destination MAC addresses
    sprintf(strsrc, "%02x:%02x:%02x:%02x:%02x:%02x",
                     (unsigned)ethheader->ether_shost[0],
                     (unsigned)ethheader->ether_shost[1],
                     (unsigned)ethheader->ether_shost[2],
                     (unsigned)ethheader->ether_shost[3],
                     (unsigned)ethheader->ether_shost[4],
                     (unsigned)ethheader->ether_shost[5]);
    src = json_object_new_string(strsrc);
    json_object_object_add(ethernet, "src", src);

    sprintf(strdst, "%02x:%02x:%02x:%02x:%02x:%02x",
                     (unsigned)ethheader->ether_dhost[0],
                     (unsigned)ethheader->ether_dhost[1],
                     (unsigned)ethheader->ether_dhost[2],
                     (unsigned)ethheader->ether_dhost[3],
                     (unsigned)ethheader->ether_dhost[4],
                     (unsigned)ethheader->ether_dhost[5]);
    dst  = json_object_new_string(strdst);
    json_object_object_add(ethernet, "dst", dst);


    //Add the lower network layer
    networklayer = json_object_new_object();
    getJsonNetworkLayer(header, packet, ethheader, networklayer);
    json_object_object_add(ethernet, "network", networklayer);

    return;
}

//Create a Json object representing an IPv4 packet
void getJsonIPv4(const struct pcap_pkthdr* header, const u_char* packet, //Entire packet header and contents
                 json_object* networkLayer) {                            //Result
    json_object *src, *dst, *protocol, *ttl;
    const struct myip* ip;
    u_int length;
    int len;

    //Jump past ethernet header which should have a fixed size so the sizeof is probably not necessary..
    ip = (struct myip*)(packet + sizeof(struct ether_header));


    //Validate ip packet------------------------------//
    length = header->len - sizeof(struct ether_header);
    //check if length is valid
    if(length < sizeof(struct myip)) { return;}
    //check for invalid header length
    if(IP_HL(ip) < 5) { return;}
    //check if as many bytes as claimed
    if(length < ntohs(ip->ip_len)) { return;}
    //End validation----------------------------------//


    //Source and destination IP addresses
    src = json_object_new_string(inet_ntoa(ip->ip_src));
    dst = json_object_new_string(inet_ntoa(ip->ip_dst));

    json_object_object_add(networkLayer, "src", src);
    json_object_object_add(networkLayer, "dst", dst);

    //Time to live
    char tmp[50];
    ttl = json_object_new_string(tmp);
    json_object_object_add(networkLayer, "time-to-live", ttl);




    //protocol in hex
    //char tmp[50];
    //sprintf(tmp,"%x",ip->ip_p);
    //protocol = json_object_new_string(tmp);
    //json_object_object_add(networkLayer, "protocol", protocol);

    //Add transport layer
    switch (ip->ip_p) {
        case 0x06: getJsonTCP();break;
        case 0x11: getJsonUDP();break;
        default: json_object_object_add(networkLayer, "protocol", json_object_new_object());
    }

    return;
}

getJsonTCP() {

}

//Print to stdout a Json representation of a packet
void writeJsonPacket(const struct pcap_pkthdr* header, const u_char* packet, //Entire packet header and contents
                     int count) {                                            //Number to label packet as being
    json_object *jpacket = json_object_new_object();
    getJsonPacketLayer(header, packet, count, jpacket);
    printf("%s\n\n",json_object_to_json_string(jpacket));
    return;
}

//Callback function to be used with pcap_loop/ pcap_dispatch to process a single packet.
void jsonPacketCallback (u_char* extraArgs,                                        //Space to pass additional arguments to callback
                         const struct pcap_pkthdr* header, const u_char* packet) { //Packets header and contents
    //Print numbered Json representation of all packets
    static int count = 1;
    writeJsonPacket(header, packet, count);
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
