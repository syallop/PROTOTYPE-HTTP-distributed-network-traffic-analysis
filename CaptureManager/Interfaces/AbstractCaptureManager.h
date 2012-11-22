#ifndef ABSTRACTCAPTUREMANAGER_H
#define ABSTRACTCAPTUREMANAGER_H

/**
 * The AbstractCaptureManager class provides an interface the capture managers should implement.
 * A capture manager is something that can manage multiple capturers.
 */
#include <string>
#include <vector>

using std::string;
using std::vector;

class AbstractCaptureManager {
    public:
        virtual string getCaptures() = 0;        //Ask for a description of the capturers it's managing
        virtual string getCapture(int capId) = 0;//Ask for the parsed packets produced by a capture

        virtual int newCapture(string type, vector<string> params) = 0;
        virtual string getCapturerTypes() = 0;   //Ask for a description of the recognised capturer types

        virtual void endCaptures() = 0;        //Ask for all managed capturers to be ended and unmanaged
        virtual void endCapture(int capId) = 0;//Ask for a specific capturer to be ended and unmanaged

        virtual void tick() = 0; //Ask the manager to update its internal state. Will often include ticking all managed capturers

};

#endif
