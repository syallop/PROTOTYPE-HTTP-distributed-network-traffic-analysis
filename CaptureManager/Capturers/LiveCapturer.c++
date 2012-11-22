/*
 * Defines a LiveCapturer class, an implementation of AbstractCapturer which allows for the
 * capturing and processing of PCAP data into JSON.
 *
 * Implementation:
 * - Creates a new, live running capture.
 * - Discards packets from internal queue after returning them. I.e. only stores packets since last request.
 */

#include "LiveCapturer.h"
#include "../PcapConversion/pcapToJson.h"
#include <string>
#include <sstream>
#include <iostream>
using std::string;
using namespace std;
using boost::thread;

//Construct a static capturer using default parameters if not supplied
LiveCapturer::LiveCapturer(string device="eth0",
                           string ifilter="",
                           int optimise=0) {

    filter = ifilter.c_str();

    pcap_lookupnet(device.c_str(), &ipaddr, &netmask, errbuf);

    //Open a handle to the capture device
    handle = pcap_open_live(device.c_str(), PCAP_ERRBUF_SIZE, 0, -1, errbuf);
    if(handle == NULL) {
        fprintf(stderr, "Could not open device for capture: %s\n", errbuf);
        return;
    }

    //Attempt to compile and apply a bpf format filter to the capture
    if(pcap_compile(handle, &program, filter, optimise, netmask) == -1) {
        fprintf(stderr, " Filter compilation failed: %s\n", pcap_geterr(handle));
    }
    if(pcap_setfilter(handle, &program) == -1) {
        fprintf(stderr, " Setting filter failed: %s\n", pcap_geterr(handle));
    }

    alive = true;
    cout << "LOG: static capturer constructed" << endl;
}

//Destroy the packet capturer
LiveCapturer::~LiveCapturer() {
    cout << "LOG: Static capturer destroyed" << endl;
    return;
}

//Parse up to maxPackets from the file into the storage
void LiveCapturer::tick(int maxPackets) {
    thread tickThread(&LiveCapturer::tickThread, this, maxPackets);
}
void LiveCapturer::tickThread(int maxPackets) {
    json_object* jsonArray = json_object_new_array();

    //Process up to maxPackets into the jsonArray
    pcap_dispatch(handle, maxPackets, livePcapCallback, (u_char*) jsonArray);

    //(Incorrectly) add the json into the queue
    //TODO generate valid json. Can currently produce [p1,p2][p3,p4]
    jsonQueue.push(json_object_to_json_string(jsonArray));
    cout << "LOG: live capturer ticked" << endl;
}

//Parses a given PCAP packet to a json representation and stores it in the jsonArray
//that has been provided as storage
void livePcapCallback(u_char* jsonArray, const struct pcap_pkthdr* pcapHeader, const u_char* pcapPayload){
    static int count = 1;
    json_object* jsonPacket = json_object_new_object();

    //Parse the pcap packet into a json object which is stored in jsonPacket
    getJsonPacket(pcapHeader, pcapPayload, count, jsonPacket);

    //Add the jsonPacket into the array so that it can be accessed by the caller
    json_object_array_add((json_object*)jsonArray, jsonPacket);
    count++;
    return;
}

//Construct and return a string representing in json the packets parsed so far.
//Remove all returned packets from the queue
string LiveCapturer::getParsedPackets() {
    string output = "[";
    cout << "LOG: capturer received request for packets" << endl;

    //If the queue isn't empty, construct a list of lists of packets.
    //I.e. [ [{1,..},{2,..}], [{3,..},{4,..}]]
    if(!jsonQueue.empty()){
        output += jsonQueue.front();
        jsonQueue.pop();

        while(!jsonQueue.empty()){
            output += ", ";
            output += jsonQueue.front();
            jsonQueue.pop();
        }
    }
    output += "]";
    return output;
}
