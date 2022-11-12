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
#include "arguments.h"

using namespace std;

/**
 * Parse arguments
 * 
 * @param argc an integer that indicates how many arguments were entered on the command line
 * @param argv argument vector - contains the arguments passed to a program through the command line
*/
Args argumentsParsing(int argc, char *argv[], Args args) {

    string IPAddr;
    int option_index = 0;
    while(( option_index = getopt(argc, argv, "f:c:a:i:m:")) != -1) {
        switch(option_index) {
            case 'f': // parsed file name or STDIN
                args.file = optarg;
                break; 
            case 'c': 
                IPAddr = getIPAddrFromName(optarg);
                IPAddr = validateIPAddress(IPAddr);
                args.ipAddress = IPAddr;
                break;
            case 'a': // active timer
                args.activeTimer = stoi(optarg) * 1000;
                break;
            case 'i': // inactive timer
                args.inactiveTimer =  stoi(optarg) * 1000;
                break;
            case 'm': // size of the flow cache
                args.flowCache =  stoi(optarg);
                break;
        }
    }

    return args;
}

/**
 * Resolves IP address from the given www address
 * 
 * @param inputName given www address by the user
 */ 
string getIPAddrFromName(char *inputName) {

    string IPAddr;
    struct hostent *hostName = gethostbyname(inputName);
    if (hostName) {
        IPAddr = inet_ntoa(*((struct in_addr*) hostName->h_addr_list[0])); 
    } else {
        return inputName;
    }    
    return IPAddr;
}

string validateIPAddress(string addr) {

    // IP Adress or hostname of the collector
    regex ipv4("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\:\\d{1,4}");

    // Regex expression for validating IPv6
    regex ipv6("((([0-9a-fA-F]){1,4})\\:){7}([0-9a-fA-F]){1,4}");

    if (regex_match(addr, ipv4)) {
        return addr;

    } else if (regex_match(addr, ipv6)) {
        return addr;

    } else {
        cout << "regex  doesnt match" << endl;
        exit(1);
    }

}