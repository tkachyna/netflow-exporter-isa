#include <iostream>
#include <getopt.h>
#include <string.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <map>
#include <unistd.h>
#include <netdb.h>
#include <err.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <tuple>
#include <bits/stdc++.h>
#include "client.h"

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
int setUDPClient() {

    int sock;  // socket descriptor
    long long i;
    struct sockaddr_in server, from; // address structures of the server and the client
    struct hostent *servent;    

    memset(&server,0,sizeof(server)); // erase the server structure
    server.sin_family = AF_INET; 

    if ((servent = gethostbyname("127.0.0.1")) == NULL) // check the firstPacketTime parameter
        errx(1,"gethostbyname() failed\n");
    
    memcpy(&server.sin_addr,servent->h_addr,servent->h_length);

    server.sin_port = htons(8070);        
    if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1)   //create a client socket
        err(1,"socket() failed\n");
  
    printf("* Server socket created\n");

    printf("* Creating a connected UDP socket using connect()\n");                
    // create a connected UDP socket
    if (connect(sock, (struct sockaddr *)&server, sizeof(server))  == -1)
        err(1, "connect() failed");

    return sock;

}