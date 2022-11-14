/**
 *  ===================================================================================
 * 
 *  ISA Project - Implementation of NetFlow exporer
 *  @author Tadeas Kachyna <xkachy00@fit.vutbr.cz>
 *  @date 14.11.2022
 *  @file arguments.cpp
 * 
 *  @brief Parsing program arguments
 *  
 * ====================================================================================
 */

#include<iostream>
#include<getopt.h>
#include<string.h>
#include<bits/stdc++.h>
#include<netdb.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<tuple>
#include"arguments.hpp"
using namespace std;

/**
 * Parse arguments
 * 
 * @param argc an integer that indicates how many arguments were entered on the command line
 * @param argv argument vector - contains the arguments passed to a program through the command line
 * @param args arguments' structure which holds them
*/
Arguments argumentsParsing(int argc, char *argv[], Arguments args) {

    string ipAddress;
    int optionIndex = 0;
    while(( optionIndex = getopt(argc, argv, "f:c:a:i:m:h")) != -1) {
        switch(optionIndex) {
            case 'h':
                printHelp();  
                exit(0);
            case 'f': // parsed file name or STDIN
                args.file = optarg;
                break; 
            case 'c': 
                ipAddress = resolveIPAddrFromName(optarg);
                tie(args.ipAddress, args.port) = resolveHostPort(ipAddress);
                break;
            case 'a': // active timer
                args.activeTimer = stoi(optarg) * 1000; // transfer to miliseconds
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
 * Resolves ip address and port from a string containing both of them
 * 
 * @param ipAddress string containing ip address and port
 * 
 * @return host ip address
 * @return post port
 */ 
tuple<string, string>resolveHostPort(string ipAddress) {
    string host;
    string port;

    if (ipAddress[0] == '[') { // ipv6 address
        const size_t pos = ipAddress.find(']');
        host = ipAddress.substr(1, pos-1);
        port = ipAddress.substr(pos+2);

    } else if (count(ipAddress.begin(), ipAddress.end(), ':') > 1) { // ipv6 address without port
        host = ipAddress;
        port = "8070";

    } else { // ipv4 adress
        const size_t pos = ipAddress.find(':');
        host = ipAddress.substr(0, pos);
        if (pos != string::npos) {
            port = ipAddress.substr(pos+1);

        } else {
            port = "8070";

        }
    }  

    return make_tuple(host, port);
}

/**
 * Resolves IP address from the given www address
 * 
 * @param inputName given www address by the user
 */ 
string resolveIPAddrFromName(char *inputName) {

    string IPAddr;
    struct hostent *hostName = gethostbyname(inputName);
    if (hostName) {
        IPAddr = inet_ntoa(*((struct in_addr*) hostName->h_addr_list[0])); 
    } else {
        return inputName;
    }    
    return IPAddr;
}

/**
 * A function to show the quick help - how to run the program.
 */ 
void printHelp() {
    cout << "----------------------------------------------------------------------------------------------------------------------" << endl;
    cout << "Netflow Exportet Quick Help" << endl;
    cout << "----------------------------------------------------------------------------------------------------------------------" << endl;
    cout << " >> How to run the program:" << endl;
    cout << " >> ./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]" << endl;
    cout << " -f name of the analyzed file or STDIN" << endl;
    cout << " -f collector address" << endl;
    cout << " -a active time in seconds" << endl;
    cout << " -i inactive time in seconds" << endl;
    cout << " -m size of the flow cache" << endl;
    cout << " >> all arguments are optional" << endl;
    cout << "----------------------------------------------------------------------------------------------------------------------" << endl;
    cout << "For more visit please the README.md file or type 'man -l flow.1' to display a man page" << endl;
    cout << "----------------------------------------------------------------------------------------------------------------------" << endl;
}