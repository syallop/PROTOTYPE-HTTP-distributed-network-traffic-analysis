#include <Capturer.h>
#include <pcapToJson.h>
#include <string>
using std::string;

//TODO
//Constructs a packets capturer with some default arguments
Capturer::Capturer() {
    return;
}
//TODO contructor that accepts arguments

//TODO
//Destroy a packet capturer
Capturer::~Capturer() {
    return;
}

//TODO
//Called to ask capturer to parse up to maxPacket number of packets into its storage
void Capturer::tick(int maxPackets) {
    return;
}

//TODO
//Returns a Json string representing the packets parsed so far.
string Capturer::getParsedPackets() {
    return "";
}


