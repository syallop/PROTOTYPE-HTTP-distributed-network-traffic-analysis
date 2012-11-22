/**
 * The AbstractCaptureManager class provides an interface that a capture manager object
 * should implement.
 */

class AbstractCaptureManager {
    public:
        virtual string getCaptures() = 0;
        virtual string getCapture(int capId) = 0;

        //TODO add arguments to initalise a new capturer with to interface
        virtual int newCapture() = 0;

        virtual void endCaptures() = 0;
        virtual void endCapture(int capId) = 0;
};
