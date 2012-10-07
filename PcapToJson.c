#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <time.h>

#include <sys/socket.h>
#include <arpa/inet.h>

//Attempt to apply a filter to a pcap handle. May fail.
int compileAndSetFilter( pcap_t* handle, char filter[], int optimise, bpf_u_int32 netmask) {
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

void printPacketStats(struct pcap_pkthdr* header) {
    printf(" Packet has length: %d\n", header->len);
    printf(" Packet has timestamp: %d\n", header->ts.tv_sec);
}

void printEthernetHeader(struct ether_header* ethheader) {
    u_char* ptr;
    int i;

    printf(" Destination address: ");
    ptr = ethheader->ether_dhost;
    i = ETHER_ADDR_LEN;
    do {
        printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":", *ptr++);
    } while(--i>0);
    printf("\n");


    printf(" Source Address     : ");
    ptr = ethheader->ether_shost;
    i = ETHER_ADDR_LEN;
    do{
        printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--i>0);
    printf("\n");

}

//Try to identify the contents of the ethernet header. Incomplete matches.
int printEthernetContents(struct ether_header* ethheader) {
    printf("   Ethernet type: %x:", ntohs(ethheader->ether_type));
    switch(ntohs(ethheader->ether_type)) {
        case ETHERTYPE_IP:
            printf("IPV4");break;
        case ETHERTYPE_ARP:
            printf("ARP");break;
        case ETHERTYPE_IPV6:
            printf("IPV6");break;
        default:
            printf("Unknown\n");
            return 1;
    }
    printf("\n");
    return 0;
}

void packetCallback(u_char* extraArgs, const struct pcap_pkthdr* header, const u_char* packet) {
    static int count = 1;
    struct ether_header* ethheader = (struct ether_header* ) packet;

    printf("Packet number: %d {\n",count);count++;
    printEthernetHeader(ethheader);
    printEthernetContents(ethheader);
    printf("}\n\n");
}

int main(int argc, char *argv[]) {
    pcap_t* handle;                //Handle to a PCAP source
    char errbuf[PCAP_ERRBUF_SIZE]; //Buffer for PCAP errors
    char filter[] = "";            //Filter to apply to PCAP source
    int optimise = 1;              //Whether to optimise the filter
    bpf_u_int32 netmask = 0xFFFFFF00;
    char inputfile[] = "capture.pcap";

    //Open a handle to a hardcoded file
    handle = pcap_open_offline(inputfile, errbuf);
    if(handle == NULL) {
        fprintf(stderr, " Couldn't open file for capture: %s\n", errbuf);
        return 1;
    }

    //Attempt to apply a specified filter
    if (compileAndSetFilter(handle, filter, optimise, netmask) != 0){return 1;}


    //Loop a callback function over each packet
    pcap_loop(handle, -1,packetCallback, NULL);
    printf("\n");

    pcap_close(handle);
    return 0;
}
