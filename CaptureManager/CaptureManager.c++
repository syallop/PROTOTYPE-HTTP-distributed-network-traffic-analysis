/**
 *  Function definitions of CaptureManager (which implements AbstractCaptureManager)
 */
#include <CaptureManager.h>
using std::string;

//TODO
//List all capturers in the map
string getCaptures() {
    //Iterate through <id,capturer> map
    //return string describing the available capturers
    return "";
}

//TODO
//Get a specified captures output
string getCapture(int capId) {
    //Lookup capturer in <id,capturer> map using given capId
    //Call popBuffer() on capturer
    //Return retrieved json string
    return "";
}

//TODO
//Create a new capture returning its Id
int newCapture() {
    //using parameters passed to the function, create a new capturer
    //assign it a new id and add it to the <id,capturer> map
    //if successful return the id
    return 0;
}

//TODO
//End all captures
void endCaptures() {
    //Destroy each capturer in the map
    //Clear the map
    return;
}

//TODO
//End specified capture
void endCapture(int capId) {
    //Look up capId in map.
    //If exists then destroy that capturer
    //remove capturer from map
    return;
}
