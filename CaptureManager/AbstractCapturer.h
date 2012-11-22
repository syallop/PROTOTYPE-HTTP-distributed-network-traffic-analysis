/*
 * The AbstractCapturer class provides an interface that a capturer object should implement
 */

class AbstractCapturer {
    public:
        virtual void tick(int maxPackets) = 0;
        virtual string getParsedPackets() = 0;
};
