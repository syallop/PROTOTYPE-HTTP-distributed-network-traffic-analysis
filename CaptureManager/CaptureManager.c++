/**
 *  Defines a CaptureManager class, an implementation of AbstractCaptureManager
 *  which allows for management of multiple capturers.
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
using boost::thread;

//Construct the captureManager with default arguments
CaptureManager::CaptureManager() {
    cout << "LOG: CaptureManager: constructed" << endl;
    capturerTypes["static"] = "A capture parsed from an existing pcap file";
    capturerTypes["live"] = "A capture made in real time over a network interface";
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
        it->second->tick(10);
    }
}

//Construct and return a string describing all of the captures we're managing
string CaptureManager::getCaptures() {
    stringstream out;

    cout << "LOG: CaptureManager: creating capturelist string" << endl;

    //Construct the string
    out << "[";
    for(capturesIterator it = captures.begin(); it != captures.end(); it++) {
        out << "   { \"Id\": " << it->first << ", \"type\":\"UNKNOWN\"},";
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
//0 returned to indicate error
int CaptureManager::newCapture(string type, vector<string> params) {
    cout << "LOG: CaptureManager: Asked to add capturer of type: " << type << endl;

    if(type == "static"){

        if(params.size() < 3){
            cout << "LOG: CaptureManager: filename, filter and optimisation should be passed to a static capturer" << endl;
            return 0;
        } else {
            string filename = params[0];
            string filter   = params[1];
            int    optimise = atoi(params[2].c_str());
            cout << "LOG: filename=" << filename << " filter=" << filter << " optimise=" << optimise << endl;

            AbstractCapturer *c = new StaticCapturer(filename, filter, optimise);
            if(c->start()){
                captures[++lastId] = c;
            } else {
                return 0;
            }

        }

    } else if(type == "live"){

        if(params.size() < 3){
            cout << "LOG: CaptureManager: interface and optimisation should be passed to a live capturer" << endl;
            return 0;
        } else {
            string device   = params[0];
            string filter   = params[1];
            int    optimise = atoi(params[2].c_str());
            cout << "LOG: devicename=" << device << " filter=" << filter << " optimise=" << optimise << endl;

            AbstractCapturer *c = new LiveCapturer(device, filter, optimise);
            if(c->start()){
                captures[++lastId] = c;
            } else {
                return 0;
            }

        }
    } else {

        cout << "LOG: CaptureManager: type not recognised." << endl;
        return 0;

    }


    return lastId;
}

//Construct and return a string representing the capturer types that this manager supports
string CaptureManager::getCapturerTypes(){
    cout << "LOG: CaptureManager: Asked to describe supported capturer types" << endl;

    stringstream out;
    out << "[";
    for(capturerTypeIterator it = capturerTypes.begin(); it != capturerTypes.end(); it++) {
        out << "    { \"Type\": \"" << it->first << "\", \"Description\": \"" << it->second << "\"},";
    }
    out << "]";

    return out.str();
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
