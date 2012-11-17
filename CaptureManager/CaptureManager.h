#ifndef CAPTUREMANAGER_H
#define CAPTUREMANAGER_H

#include "./Interfaces/AbstractCaptureManager.h"
#include "./Interfaces/AbstractCapturer.h"

#include "./Capturers/StaticCapturer.h"
#include "./Capturers/LiveCapturer.h"
//etc

#include <string>
#include <map>


using std::string;
using std::map;

class CaptureManager : public AbstractCaptureManager {
    public:
        CaptureManager();
        ~CaptureManager();

        void tick();

        string getCaptures();
        string getCapture(int capId);

        int newCapture(string type);

        void endCaptures();
        void endCapture(int capId);
    private:
        //Map of capturer identifiers to capturers
        map<int, AbstractCapturer*> captures;

        //Alias for an iterator over the map
        typedef map<int, AbstractCapturer*>::iterator capturesIterator;

        //The last Id we gave to a capturer stored in the map
        int lastId = 0;
};


#endif
