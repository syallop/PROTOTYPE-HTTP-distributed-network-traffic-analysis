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

/* Function prototypes of the form 'getJson--Layer' tend to:
 * - Take pointers to the entire packet header and contents as their first two
 *   arguments. This is a lazy way to allow access to the entire packet as
 *   layers are decended.
 * - Take a pointer to a json_object as their last argument. This is intended to
 *   be the storage for the functions output.
*/

/* For reference, layer order is: PCAP Header:datalink:network:transport
 * E.G:
 *     PCAP: size arrival time ...
 *     Datalink: ethernet(srcMAC dstMAC)/ ...
 *     Network: IPv4(srcIP, dstIP, ...)/ IPv6(...)
 *     Transport: TCP(...)/ UDP(...)
 */

//Packet layer functions=======================================================//
void getJsonPacketLayer(const struct pcap_pkthdr* header, const u_char* packet,
                        int count,
                        json_object* jpacket);
//=============================================================================//

//Datalink layer=================================================================//
void getJsonDatalinkLayer(const struct pcap_pkthdr* header, const u_char* packet,
                          json_object* datalink);

void getJsonEthernet(const struct pcap_pkthdr* header, const u_char* packet,
                     const struct ether_header* ethheader,
                     json_object* ethernet);
//===============================================================================//

//Network layer=================================================================//
void getJsonNetworkLayer(const struct pcap_pkthdr* header, const u_char* packet,
                         const struct ether_header* ethheader,
                         json_object* networkLayer);
void getJsonIPv4(const struct pcap_pkthdr* header, const u_char* packet,
                 json_object* networkLayer);
void getJsonIPv6();//TODO
void getJsonARP();//TODO
//==============================================================================//

//Transport layer===============================================================//
void getJsonTransportLayer(json_object* transportLayer);//TODO
void getJsonTCP();//TODO
void getJsonUDP();//TODO
//==============================================================================//


//IP header without options.
struct myip {
    u_int8_t ip_vhl;             //Header length, version
    #define IP_V(ip) (((ip)->ip_vhl & 0xf0) >> 4)
    #define IP_HL(ip) ((ip)->ip_vhl & 0x0f)
    u_int8_t    ip_tos;          //'Type of service'/DSCP
    u_int16_t   ip_len;          //Total length
    u_int16_t   ip_id;           //Identification
    u_int16_t   ip_off;          //Fragment offset
    #define IP_DF 0x4000         //DF 'dont fragment' flag
    #define IP_MF 0x2000         //MF 'more fragment' flag
    #define IP_OFFMASK 0x1fff    //Mask for fragmenting bits
    u_int8_t    ip_ttl;          //Time to live
    u_int8_t    ip_p;            //Protocol
    u_int16_t   ip_sum;          //Checksum
    struct in_addr ip_src,ip_dst;//Source and destination address
};
