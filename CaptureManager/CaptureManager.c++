/**
 *  Defines a CaptureManager class, an implementation of AbstractCaptureManager
 *  which allows for management of multiple capturers.
 *
 *  Limitations/ incomplete code:
 *  - Only creates StaticCapturers with their default parameters
 *  - Always ticks capturers to process no more than one packet at once
 */
#include "CaptureManager.h"

#include <iostream>
#include <sstream>
#include <utility>
#include <functional>
using std::cout;
using std::endl;
using std::string;
using std::map;
using std::stringstream;
using std::pair;

//Construct the captureManager with default arguments
CaptureManager::CaptureManager() {
    cout << "LOG: CaptureManager: constructed" << endl;
}

//Destroy the captureManager
CaptureManager::~CaptureManager() {
    cout << "LOG: CaptureManager: destroyed" << endl;
}

//Updates the captureManagers internal state
void CaptureManager::tick() {
    cout << "LOG: CaptureManager: ticking managed captures" << endl;
    //Tick all managed captures, asking them to update themselves potentially processing more packets
    for(capturesIterator it = captures.begin(); it != captures.end(); it++) {
        it->second->tick(1);
    }
}

//Construct and return a string describing all of the captures we're managing
string CaptureManager::getCaptures() {
    stringstream out;

    cout << "LOG: CaptureManager: creating capturelist string" << endl;

    //Construct the string
    out << "[";
    for(capturesIterator it = captures.begin(); it != captures.end(); it++) {
        out << "   { \"Id\": " << it->first << ", \"type\":\"static-file\"},";
    }
    out << "]";

    return out.str();
}

//Construct and return a string representing a requested captures output
string CaptureManager::getCapture(int capId) {
    capturesIterator it = captures.find(capId);

    cout << "LOG: CaptureManager: creating json string for requested capturer" << endl;

    //If the specified capture does not exist, return a json empty list
    if(it == captures.end()) {
        return "[]";
    } else {
        return it->second->getParsedPackets();
    }
}

//Create a new capture and return the ID we gave it
int CaptureManager::newCapture() {
    cout << "LOG: CaptureManager: Adding new capturer" << endl;
    captures[++lastId] = new StaticCapturer("packets.pcap","",0);
    return lastId;
}

//Ask all capturers we're managing to end and clear our map
void CaptureManager::endCaptures() {
    cout << "LOG: CaptureManager: Ending all capturers" << endl;
    for(capturesIterator it = captures.begin(); it != captures.end(); it++) {
        delete it->second;
    }
    captures.clear();
}

//Ask a specified capture to end and clear it from our map
void CaptureManager::endCapture(int capId) {
    cout << "LOG: CaptureManager: Ending specified capturer" << endl;

    capturesIterator it = captures.find(capId);
    //find returns end if we're not managing the requested ID
    if(it != captures.end()) {
        delete it->second;
        captures.erase(it);
    }
}
