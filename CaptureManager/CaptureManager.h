#ifndef CAPTUREMANAGER_H
#define CAPTUREMANAGER_H

#include "./Interfaces/AbstractCaptureManager.h"
#include "./Interfaces/AbstractCapturer.h"

#include "./Capturers/StaticCapturer.h"
#include "./Capturers/LiveCapturer.h"
//etc

#include <string>
#include <map>
#include <vector>


using std::string;
using std::map;
using std::vector;

class CaptureManager : public AbstractCaptureManager {
    public:
        CaptureManager();
        ~CaptureManager();

        void tick();

        string getCaptures();
        string getCapture(int capId);

        int newCapture(string type, vector<string> params);
        string getCapturerTypes();

        void endCaptures();
        void endCapture(int capId);
    private:
        //Map of capturer identifiers to capturers
        map<int, AbstractCapturer*> captures;

        //Alias for an iterator over the map
        typedef map<int, AbstractCapturer*>::iterator capturesIterator;

        //Map of supported capturer type names to descriptions. Used to tell clients what
        //capturer types 'newCapture()' will accept.
        map<string, string> capturerTypes;

        //Alias for an iterator over the map
        typedef map<string, string>::iterator capturerTypeIterator;


        //The last Id we gave to a capturer stored in the map
        int lastId = 0;
};


#endif
