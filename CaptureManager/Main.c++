/*
 * Entry point to program. Responsible for:
 * - Initialising a captureManager
 * - Maintaining a network connection on which to accept commands
 * - Parsing commands to actions upon the captureManager and returning responses
 */

#include "Main.h"
using namespace std;
using boost::thread;
#include <boost/tokenizer.hpp>

//Program entry point
int main(int argc, char *argv[]) {
    int port = 9999;

    //Parse port to run captureManager on
    int c;
    while((c = getopt(argc,argv,"p:"))!= -1) {
        switch(c) {
            case 'p':
                port = atoi(optarg);
                break;
        }
    }

    Program* p = new Program(port,10);
    p->run();
    return 0;
}

//Initialise the program, using defaults if not provided
Program::Program(int iport=9999, int iupdateDurationSeconds=10){
    port                       = iport;
    updateDurationSeconds      = iupdateDurationSeconds;

    bzero( (char *)&serv_addr, sizeof(serv_addr));//Clear the address structure
    serv_addr.sin_family = AF_INET;               //Use IP sockets
    serv_addr.sin_addr.s_addr = INADDR_ANY;       //Accept connections on all Interfaces/
    serv_addr.sin_port = htons(port);             //Set the port to listen on
    clilen = sizeof(cli_addr);                    //Define the length of the client address structure
}

//Destructor. Clean up
Program::~Program(){
    delete manager;
}

//Run the program logic.
void Program::run(){
    manager = new CaptureManager();

    //Create a thread to ask the manager to update itself every interval
    thread tickThread(&Program::tickCaptureManager, this, updateDurationSeconds);

    //Attempt to open and bind to a socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("ERROR opening socket");exit(1);
    }
    if ( bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0){
        perror("ERROR on binding");exit(1);
    }

    //Listen on the socket
    listen(sockfd,5);
    cout << "LOG: Accepting connections on port " << port << endl;

    //Forever, accept new connections and pass them off to a thread to be handled
    while(true){
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0){
            perror("ERROR on accept");exit(1);
        }

        cout << "LOG: Connection established." << endl;

        //Handle the connection concurrently to listening for more by using a new thread
        thread connectionThread(&Program::handleConnection, this, newsockfd);
        //connectionThread.join();//Only handle one connection at once
    }

    //Close the socket
    close(sockfd);
}



//Given a socket descriptor to a connection with a client, handle the interaction
void Program::handleConnection(int lsockfd) {
    char messageBuffer[64];
    string response;
    int numberBytes;

    //Read a request, parse it and reply with a newline terminated response until the request
    //matches 'exit'
    do{
        //Initialise buffer and block until data is read into the buffer
        bzero(messageBuffer,64);
        numberBytes = read(lsockfd, messageBuffer, 63);
        if (numberBytes < 0) {
            perror("ERROR reading from socket");
            close(lsockfd);
            return;
        }
        cout << "LOG: Received: " << messageBuffer << endl;

        //Parse the message
        response = commandParser(messageBuffer) + "\n";
        cout << "LOG: Responding with: " << response;

        numberBytes = write(lsockfd,response.c_str(), response.length());
        if (numberBytes < 0) {
            perror("ERROR writing to socket");
            close(lsockfd);
            return;
        }
    }while(!matches(messageBuffer, "exit"));

    //Close the socket before exiting
    cout << "LOG: We've been asked to exit" << endl;
    close(lsockfd);
}

//Given a string, return a vector of tokenizing it delimited on the space character
vector<string> getSpaceDelimTokens(string s){
    istringstream iss(s);
    vector<string> tokens;

    copy(istream_iterator<string>(iss),
         istream_iterator<string>(),
         back_inserter<vector<string> >(tokens));

    return tokens;
}

//Given a command string, return an appropriate response, most likely from querying the capture manager
//Warning: horrible code.
string Program::commandParser(char input[64]) {
    string sinput = input;//Work with cpp strings instead of char arrays
    vector<string> tokens;//Tokens parsed from input string
    string command;

    //Tokenize the input string. The first word is the command. The rest are parameters
    tokens = getSpaceDelimTokens(input);
    if(tokens.empty()){
        return "LOG: No command parsed";
    } else {
        command = tokens.at(0);
    }

    /*Try and match the command string*/
    if (command == "getcapturertypes"){

        cout << "LOG parsed as request for a list of supported capturer types" << endl;
        return manager->getCapturerTypes();

    } else if (command == "getcaptures"){

        cout << "LOG: parsed as request for a list of captures" << endl;
        return manager->getCaptures();

    }else if (command == "getcapture"){

        cout << "LOG: parsed as a request for the contents of a capture" << endl;
        if(tokens.size() >= 2){
            int capId = atoi(tokens[1].c_str());
            return manager->getCapture(capId);
        } else{
            return "Provide an ID to retrieve as the first parameter.";
        }

    }else if (command == "newcapture"){

        cout << "LOG: parsed as request for a new capture to be created" << endl;

        if(tokens.size() >= 2){
            string type = tokens[1];
            tokens.erase(tokens.begin(), tokens.begin()+2);
            vector<string> additionalParams = tokens;

            char response[10];
            sprintf(response, "%d", manager->newCapture(type, additionalParams));
            return response;
        } else {
            return "Provide a capture type as the first parameter";
        }

    }else if (command == "endcaptures"){

        cout << "LOG: parsed as a request to end all captures" << endl;
        manager->endCaptures();
        return "success";

    }else if (command == "endcapture"){

        cout << "LOG: parsed as a request to end a given capture" << endl;

        if(tokens.size() >= 2){
            int capId = atoi(tokens[1].c_str());
            manager->endCapture(capId);
            return "success";
        } else{
            return "Provide an ID to end as the first parameter.";
        }

    }else if(command == "exit"){
        cout << "LOG: parsed as a request to end comunication" << endl;
        return "Bye";
    }else {
        cout << "LOG: request not parsed" << endl;
        return "CommandNotFound";
    }
}



//True when the first char array contains the second
bool Program::matches(char first[], char second[]) {
    if(strstr(first,second) == NULL){
        return false;
    }
    return true;
}

//Forever, ask the capture manager to update its state every interval
void Program::tickCaptureManager(int interval) {
    while(true) {
        manager->tick();
        sleep(interval);
    }
}
