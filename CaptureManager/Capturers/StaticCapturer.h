#ifndef STATICCAPTURER_H
#define STATICCAPTURER_H

#include "../Interfaces/AbstractCapturer.h"
#include <queue>
#include <string>
using std::string;
using std::queue;

#include <pcap.h>
void pcapCallback(u_char* jsonArray,
                  const struct pcap_pkthdr* pcapHeader,
                  const u_char* pcapPayload);

class StaticCapturer : public AbstractCapturer {
    public:
        StaticCapturer(string fileName, string filter, int optimise);
        ~StaticCapturer();
        void tick(int maxPackets);
        string getParsedPackets();
    private:
        queue<string> jsonQueue;       //Storage for processed packets

        pcap_t* handle;                //Pointer to a pcap format file
        struct bpf_program program;    //Compiled filter program
        string fileName;               //Filename to be read as a capture
        char errbuf[PCAP_ERRBUF_SIZE]; //Buffer for PCAP errors
        bpf_u_int32 netmask = 0xFFFFFF00;
        char* filter = "";             //BPF format filter to apply to the capture
};

#endif
