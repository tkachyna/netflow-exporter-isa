#include<iostream>
#include<string.h>    
#include<sys/socket.h>
#include<arpa/inet.h> 
#include<netinet/in.h>
#include<unistd.h>
#include<netdb.h>
#include<err.h>
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
int setUDPClient(string host, string port);