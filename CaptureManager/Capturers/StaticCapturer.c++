/*
 * Defines a StaticCapturer class, an implementation of AbstractCapturer which allows for the
 * capturing and processing of PCAP data into JSON.
 *
 * Implementation:
 * - Acts upon a static, existing capture file.
 * - Discards packets from internal queue after returning them. I.e. only stores packets since last request.
 */

#include "StaticCapturer.h"
#include "../PcapConversion/pcapToJson.h"
#include <string>
#include <sstream>
#include <iostream>
using std::string;
using namespace std;

//Construct a static capturer using default parameters if not supplied
StaticCapturer::StaticCapturer(string ifileName="packets.pcap",
                               string ifilter="",
                               int optimise=0) {
    fileName = ifileName;
    filter = ifilter.c_str();

    //Open a handle to the pcap format file
    handle = pcap_open_offline(fileName.c_str(), errbuf);
    if(handle == NULL) {
        fprintf(stderr, "Could not open file for capture: %s\n", errbuf);
        return;
    }

    //Attempt to compile and apply a bpf format filter to the capture
    if(pcap_compile(handle, &program, filter, optimise, netmask) == -1) {
        fprintf(stderr, " Filter compilation failed: %s\n", pcap_geterr(handle));
    }
    if(pcap_setfilter(handle, &program) == -1) {
        fprintf(stderr, " Setting filter failed: %s\n", pcap_geterr(handle));
    }

    cout << "LOG: static capturer constructed" << endl;
    alive = true;
}

//Destroy the packet capturer
StaticCapturer::~StaticCapturer() {
    cout << "LOG: Static capturer destroyed" << endl;
    return;
}

//Parse up to maxPackets from the file into the storage
void StaticCapturer::tick(int maxPackets) {
    json_object* jsonArray = json_object_new_array();

    //Process up to maxPackets into the jsonArray
    pcap_loop(handle, maxPackets, pcapCallback, (u_char*) jsonArray);

    //(Incorrectly) add the json into the queue
    //TODO generate valid json. Can currently produce [p1,p2][p3,p4]
    jsonQueue.push(json_object_to_json_string(jsonArray));
    cout << "LOG: static capturer ticked" << endl;
}

//Parses a given PCAP packet to a json representation and stores it in the jsonArray
//that has been provided as storage
void pcapCallback(u_char* jsonArray, const struct pcap_pkthdr* pcapHeader, const u_char* pcapPayload){
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
string StaticCapturer::getParsedPackets() {
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
