/**
 *  ===================================================================================
 * 
 *  ISA Project - Implementation of NetFlow exporer
 *  @author Tadeas Kachyna <xkachy00@fit.vutbr.cz>
 *  @date 14.11.2022
 *  @file arguments.hpp
 * 
 *  @brief Parsing program arguments
 *  
 * ====================================================================================
 */

#include <iostream>
#include <getopt.h>
#include <string.h>
#include <netdb.h>
#include <tuple>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bits/stdc++.h>
using namespace std;

/**
 * @struct Arguments
 * @brief a struct to hold programm's arguments
 * 
 * @var file inpur file 
 * @var ipAddress ip address where the flow are goint to send 
 * @var activeTimer 
 * @var inActiveTimer
 * @var flowCache
 */
typedef struct Arguments {
    string file = "-";
    string ipAddress = "127.0.0.1";
    string port = "8070";
    uint16_t activeTimer = 60000;
    uint16_t inactiveTimer = 10000;
    size_t flowCache = 1024;
} Arguments;

Arguments argumentsParsing(int argc, char *argv[], Arguments args);

string resolveIPAddrFromName(char *inputName);

tuple<string, string> resolveHostPort(string ipAddress);

void printHelp();