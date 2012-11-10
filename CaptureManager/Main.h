#ifndef MAIN_H
#define MAIN_H

#include "CaptureManager.h"

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <map>

#include <boost/thread.hpp>
using std::map;
using std::string;

class Program {
    public:
        Program(int port, int updateDurationSeconds);
        ~Program();
        void run();
    private:
        AbstractCaptureManager* manager; //Manages a collection of capturers

        int port;                     //Network port program listens on
        int sockfd;                   //File descriptor for primary socket
        int newsockfd;                //Temporary descriptor for accepted connections over primary socket
        struct sockaddr_in serv_addr; //Servers address
        struct sockaddr cli_addr;     //Clients address
        socklen_t clilen;             //Client address structures length

        int updateDurationSeconds;    //Time to wait in seconds before asking the capture manager to refresh its state

        //Given a socket descriptor to a connection with a client, handle interaction
        void handleConnection(int sockfd);

        //Ask the capture manager to update its state every interval
        void tickCaptureManager(int interval);

        //Given a command string, return an apropriate response
        string commandParser(char command[64]);

        //Helper function for string comparison
        bool matches(char first[], char second[]);

};

#endif
