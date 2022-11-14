#include<iostream>
#include<string.h>    
#include<sys/socket.h>
#include<arpa/inet.h> 
#include<netinet/in.h>
#include<unistd.h>
#include<netdb.h>
#include<err.h>
#include"client.hpp"
using namespace std;

/****************************************************************************************
* 
*    Title: echo_udp_client_2
*    Author: Petr Matousek
*    Date: 2016, last updated 2019
*    Availability: https://moodle.vut.cz/pluginfile.php/502893/mod_folder/content/0/udp/echo-udp-client2.c?forcedownload=1
*
*    @brief Simple echo connected UDP client with two parameters and the connect() function
*    @return sock socket deskriptor
*
***************************************************************************************/
int setUDPClient(string argsHost, string argsPort) {

    int sock;  // socket descriptor
    uint16_t port = stoi(argsPort); 

    // change ipv4 address from string to char*
    char *host = new char[argsHost.length() + 1]; 
    strcpy(host, argsHost.c_str());

    // address strucuint8_ttures of the server and the client
    struct sockaddr_in server; 
    struct hostent *servent;    

    // erase the server structure
    memset(&server,0,sizeof(server)); 
    server.sin_family = AF_INET; 

    // check the firstPacketTime parameter
    if ((servent = gethostbyname(host)) == NULL) 
        errx(1,"gethostbyname() failed\n");
    
    memcpy(&server.sin_addr,servent->h_addr,servent->h_length);

    server.sin_port = htons(port);        
    if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1) //create a client socket
        err(1,"socket() failed\n");
  
    printf("* Server socket created\n");
    printf("* Creating a connected UDP socket using connect()\n");   
                 
    // create a connected UDP socket
    if (connect(sock, (struct sockaddr *)&server, sizeof(server))  == -1)
        err(1, "connect() failed");

    return sock;

}