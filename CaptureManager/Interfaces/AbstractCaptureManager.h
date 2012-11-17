#ifndef ABSTRACTCAPTUREMANAGER_H
#define ABSTRACTCAPTUREMANAGER_H

/**
 * The AbstractCaptureManager class provides an interface the capture managers should implement.
 * A capture manager is something that can manage multiple capturers.
 */
#include <string>

class AbstractCaptureManager {
    public:
        virtual std::string getCaptures() = 0;        //Ask for a description of the capturers it's managing
        virtual std::string getCapture(int capId) = 0;//Ask for the parsed packets produced by a capture

        virtual int newCapture(std::string type) = 0;//Ask for a new capturer to be created and managed. Return the Id it's been given.

        virtual void endCaptures() = 0;        //Ask for all managed capturers to be ended and unmanaged
        virtual void endCapture(int capId) = 0;//Ask for a specific capturer to be ended and unmanaged

        virtual void tick() = 0; //Ask the manager to update its internal state. Will often include ticking all managed capturers
};

#endif
