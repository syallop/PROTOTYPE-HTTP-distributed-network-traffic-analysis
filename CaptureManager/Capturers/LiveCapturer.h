#ifndef LIVECAPTURER_H
#define LIVECAPTURER_H

#include "../Interfaces/AbstractCapturer.h"
#include <queue>
#include <string>
using std::string;
using std::queue;

#include <pcap.h>

#include <boost/thread.hpp>

void livePcapCallback(u_char* jsonArray,
                  const struct pcap_pkthdr* pcapHeader,
                  const u_char* pcapPayload);

class LiveCapturer : public AbstractCapturer {
    public:
        LiveCapturer(string device, string filter, int optimise);
        ~LiveCapturer();
        void tick(int maxPackets);
        string getParsedPackets();

        bool alive = false;
    private:
        queue<string> jsonQueue;       //Storage for processed packets

        pcap_t* handle;                //Pointer to a pcap format file
        struct bpf_program program;    //Compiled filter program
        bpf_u_int32 ipaddr;            //IP address assigned to the interface we're listening on
        pcap_if_t *alldevs;
        char* dev;                     //Device we're listening on. I.e. 'wlan0','eth0'
        char errbuf[PCAP_ERRBUF_SIZE]; //Buffer for PCAP errors
        bpf_u_int32 netmask = 0xFFFFFF00;
        char* filter = "";             //BPF format filter to apply to the capture

        void tickThread(int maxPackets);
};

#endif
