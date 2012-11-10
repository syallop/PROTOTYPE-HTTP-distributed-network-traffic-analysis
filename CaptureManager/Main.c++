/*
 * Entry point to program. Responsible for:
 * - Initialising a captureManager
 * - Maintaining a network connection on which to accept commands
 * - Parsing commands to actions upon the captureManager and returning responses
 */

#include "Main.h"
using namespace std;
using boost::thread;

//Program entry point
int main() {
    Program* p = new Program(9999,10);
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


//Given a command string, return an appropriate response, most likely from querying the capture manager
//Warning: horrible code.
string Program::commandParser(char command[64]) {
    if       (matches(command, "getcaptures")){
        cout << "LOG: parsed as request for a list of captures" << endl;
        return manager->getCaptures();
    }else if (matches(command, "getcapture")){
        cout << "LOG: parsed as a request for the contents of a capture" << endl;
        return manager->getCapture(1);
    }else if (matches(command, "newcapture")){
        cout << "LOG: parsed as request for a new capture to be created" << endl;
        char tmp[10];
        sprintf(tmp, "%d", manager->newCapture());
        return tmp;
    }else if (matches(command, "endcaptures")){
        cout << "LOG: parsed as a request to end all captures" << endl;
        manager->endCaptures();
        return "success";
    }else if (matches(command, "endcapture")){
        cout << "LOG: parsed as a request to end a given capture" << endl;
        manager->endCapture(1);
        return "success";
    }else if(matches(command, "exit")){
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
