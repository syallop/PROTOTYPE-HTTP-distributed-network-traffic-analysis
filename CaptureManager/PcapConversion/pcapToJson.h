#include <pcap.h>
#include <json/json.h>

/**
 * Prototype functions for converting pcap/ network packets into a json format.
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


//=========Application layer================================================================//
int getJsonUDPPort(int port, const u_char* applicationLayer, json_object* jsonApplication);
int getJsonTCPPort(int port, const u_char* applicationLayer, json_object* jsonApplication);
void getJsonDNS(const u_char* dns, json_object* jsonDNS);
//==========================================================================================//

