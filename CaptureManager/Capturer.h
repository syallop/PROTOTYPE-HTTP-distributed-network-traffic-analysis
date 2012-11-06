/*
 * Capturer is a possible implementation of an AbstractCapturer.
 * Implemented using a circular_buffer within a queue so that only the last n
 *  parsed packets are kept in memory.
 */
#include <queue>
#include <boost/circular_buffer.hpp>
#include <string>
using std::string;

class Capturer : public AbstractCapturer {
    public:
        Capturer();
        //TODO constructor that accepts some arguments
        ~Capturer();
        void tick(int maxPackets);
        string getParsedPackets();
    private:
        typedef std::queue<string, boost::circular_buffer<string>> limited_queue;
        const int buffer_size = 100;
        limited_queue jsonQueue(boost::circular_buffer<string>(100));
};
