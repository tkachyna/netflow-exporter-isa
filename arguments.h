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
    string ipAddress = "127.0.0.1:2055";
    int activeTimer = 60000;
    int inactiveTimer = 10000;
    int flowCache = 1024;
} Args;



/**
 * Parse arguments
 * 
 * @param argc an integer that indicates how many arguments were entered on the command line
 * @param argv argument vector - contains the arguments passed to a program through the command line
*/
Args argumentsParsing(int argc, char *argv[], Args args);

/**
 * Resolves IP address from the given www address
 * 
 * @param inputName given www address by the user
 */ 
string getIPAddrFromName(char *inputName);

string validateIPAddress(string addr);
