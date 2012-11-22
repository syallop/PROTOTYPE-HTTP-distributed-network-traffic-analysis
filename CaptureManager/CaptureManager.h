/*
 * CaptureManager is a possible implementation of an AbstractCaptureManager.
 */

#include <string>

class CaptureManager : public AbstractCaptureManager {
    public:
        string getCaptures();
        string getCapture(int capId);

        int newCapture();

        void endCaptures();
        void endCapture(int capId);
    private:
        //TODO add <capId, capturer> map
};
