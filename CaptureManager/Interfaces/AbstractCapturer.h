#ifndef ABSTRACTCAPTURER_H
#define ABSTRACTCAPTURER_H

/*
 * The AbstractCapturer class provides an interface that capturers should implement.
 * A Capturer is something that parses a source of pcap data producing a string of output.
 *
 * Note: The source of the data is left to be defined by the implementor
 */
#include <string>

class AbstractCapturer {
    public:
        virtual bool start() = 0; //Ask a capturer to begin working. Return success of this attempt
        virtual void tick(int maxPackets) = 0;     //Ask a capturer to update its internal state
        virtual std::string getParsedPackets() = 0;//Ask a capturer to return parsed packets
};

#endif
