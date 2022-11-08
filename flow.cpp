/**
 *  ===================================================================================
 * 
 *  ISA Project - Implementation of NetFlow exporer
 *  @author Tadeas Kachyna <xkachy00@fit.vutbr.cz>
 *  @date 14.11.2022
 *  @file flow.cpp
 * 
 *  @brief Implementation of NetFlow protocol which is used to monitor
 *   network flow for understanding network patterns and protocol distribution
 *  
 * ====================================================================================
 */

#define __FAVOR_BSD

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
#include "flow.h"
#include <bits/stdc++.h>

using namespace std;

timeval bootTime;
bool bootTimeRec = false;
uint32_t unix_nsecs;
int flowSequence = 1;
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
int sock;

/** 
 * @struct flowInfo
 * @brief a struct to hold info about flows
 * 
 * @var networkIPSrcAddr network byte order IP source address
 * @var networkIPDstAddr network byte order IP destination address
 * @var firstPacketTime firstPacketTime occurence of the packet in the flow
 * @var lastPacketTime lastPacketTime occurence of the packet in the flow
 * @var numOfPackets number of packets in the flow
 * @var length of the flow in bytes
 * @var tos type of service
 * @var tcp_flags cumulative OR of TCP flags
 * @var prot protocol number
 */ 
typedef struct flowInfo {
    uint32_t networkIPSrcAddr;
    uint32_t networkIPDstAddr;
    timeval ts;
    long long firstPacketTime = 0;
    long long lastPacketTime = 0; 
    int numOfPackets = 0;
    int length = 0;
    int tos = 0;
    int tcp_flags = 0;
    int prot = 0;
} flowInfo;

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
    string file;
    string ipAddress = "127.0.0.1:2055";
    int activeTimer = 60;
    int inactiveTimer = 10;
    int flowCache = 1024;
} Args;


Args args; // holds programm arguments
map<tuple<string, string, int, int, string>, flowInfo> flows; // flow cache

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

/**
 * setUDPClient
 * 
 * @brief Simple echo connected UDP client with two parameters and the connect() function
 * @author Petr Matousek, 2016, lastPacketTime Updated 2019
 * 
 * @return sock socket deskriptor
 * 
 *  !!! This function was borrowed and edited from a file udp-client.c available in E-LEARNING !!!
 */ 
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

void exportToCollector(tuple<string,string,int,int,string>NF, flowInfo info, timeval ts) {

    sock = setUDPClient();
    NetFlowV5Packet packet;
    long i;


    /// calculate SysUptime
    int32_t SysUptime = (ts.tv_sec * 1000 + (ts.tv_usec + 500)/1000) - (bootTime.tv_sec * 1000 + (bootTime.tv_usec + 500)/1000);

    // converting ipv4 adress to network adress
    int lenSrcAddr = get<0>(NF).length();
    int lenDestAddr = get<1>(NF).length();
    char srcAddr[lenSrcAddr+1];
    char dstAddr[lenDestAddr+1];
    unsigned char src[sizeof(struct in_addr)];
    unsigned char dst[sizeof(struct in_addr)];
    strcpy(srcAddr, get<0>(NF).c_str());
    strcpy(dstAddr, get<1>(NF).c_str()); 
   
    
    cout << " ================== This Flow is beeing exported ==============================" << endl;
    cout << " Src Address: " << srcAddr << endl;
    cout << "Dest Address: " << dstAddr << endl;
    cout << "    Src Port: " << get<2>(NF) << endl;
    cout << "    DestPort: " << get<3>(NF) << endl;
    cout << "       firstPacketTime: " << info.firstPacketTime << endl;
    cout << "        lastPacketTime: " << info.lastPacketTime  << endl;
    cout << "   sysuptime: " << SysUptime  << endl;
    cout << "numOfPackets: " << info.numOfPackets << endl;
    cout << "      length: " << info.length  << endl;
    cout << "     boottime:" << bootTime.tv_sec << endl;
    cout << "     unix_Secs:" << ts.tv_sec<< endl;
    cout << "     unix_necs:" << ts.tv_usec * 1000 << endl;
    cout << " ================================== End =======================================" << endl;
    
    
    packet.version = htons(5);
    packet.count = htons(1);
    packet.SysUptime =  htonl(SysUptime);
    packet.unix_secs = htonl(ts.tv_sec);
    packet.unix_nsecs  =  htonl(ts.tv_usec * 1000);
    packet.flow_sequence =  htonl(flowSequence);
    packet.engine_type = 0;
    packet.engine_id = 0;
    packet.sampling_interval = htons(0);
    packet.srcaddr =  info.networkIPSrcAddr;
    packet.destaddr = info.networkIPDstAddr;
    packet.nexthop = htonl(0);
    packet.input = htons(0);
    packet.output = htons(0);
    packet.dPkts = htonl(info.numOfPackets);
    packet.length = htonl(info.length);
    packet.First =  htonl(info.firstPacketTime);
    packet.Last =  htonl(info.lastPacketTime);
    packet.srcport = htons(get<2>(NF));
    packet.dstport = htons(get<3>(NF));
    packet.pad1 = 0;
    packet.tcp_flags = 0;
    packet.prot = 0;
    packet.tos = 0;
    packet.src_as = htons(0);
    packet.dst_as = htons(0);
    packet.src_mask = htons(0);
    packet.dst_mask = htons(0);
    packet.pad2 = htons(0);

    flowSequence++;


    i = send(sock, &packet ,sizeof(NetFlowV5Packet), 0);     // send data to the server
    if (i == -1)                   // check if data was sent correctly
      err(1,"send() failed");

   
}   

void removeFlow(tuple<string, string, int, int, string>keyNF) {
    cout << "Removing flow ... " << get<0>(keyNF) << " : " << get<1>(keyNF) << " : " << get<2>(keyNF) << " : " << get<3>(keyNF) << " : " << get<4>(keyNF) << endl;
    flows.erase(keyNF);
    cout << "test2" << endl;
}

void checkFlowCache() {
    if (flows.size() == 1024) {
        flows.erase(flows.begin());
    }
}

void activeTimer(timeval ts) {
     
     long firstPacketTimePacketTime;
     for (map< tuple<string, string, int, int, string>, flowInfo>::iterator itr = flows.begin(); itr != flows.end(); ) {
        firstPacketTimePacketTime = itr->second.firstPacketTime;
        if (ts.tv_sec - firstPacketTimePacketTime > 60) {
            cout << "Active Timer Activated" << endl;
            exportToCollector(itr->first, itr->second, itr->second.ts);
            flows.erase(itr++);
        } else {
            itr++;
        }
    }
}

void inActiveTimer(timeval ts) {
    
    long lastPacketTimePacketTime;
    tuple<string, string, int, int, string>  it;
    map< tuple<string, string, int, int, string>, flowInfo>::iterator itr;
    for (itr = flows.begin(); itr != flows.end();) {
        if (ts.tv_sec - itr->second.lastPacketTime > 10) {
            it = itr->first;
            cout << "Inactive Timer Activated" << endl;
            cout << "Removing flow ... " << get<0>(itr->first) << " : " << get<1>(itr->first) << " : " << get<2>(itr->first) << " : " << get<3>(itr->first) << " : " << get<4>(itr->first) << endl;
            exportToCollector(itr->first, itr->second, itr->second.ts);
            //removeFlow(itr->firstPacketTime, itr);
            //cout << "Removing flow ... " << get<0>(itr->firs) << " : " << get<1>(keyNF) << " : " << get<2>(keyNF) << " : " << get<3>(keyNF) << " : " << get<4>(keyNF) << endl;
            flows.erase(itr++);
            cout << "test 3 " << endl;
       
        } else {
            ++itr;
        }

    }


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

/**
 * Parse arguments
 * 
 * @param argc an integer that indicates how many arguments were entered on the command line
 * @param argv argument vector - contains the arguments passed to a program through the command line
*/
void argumentsParsing(int argc, char *argv[]) {

    string IPAddr;
    int option_index = 0;
    while(( option_index = getopt(argc, argv, "f:c:a:i:m")) != -1) {
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
                args.activeTimer = stoi(optarg);
                break;
            case 'i': // inactive timer
                args.inactiveTimer =  stoi(optarg);
                break;
            case 'm': // size of the flow cache
                args.flowCache =  stoi(optarg);
                break;
        }
    }
}

/**
 *  Create new flow, if one with the key already exists,
 *  find it and agregate values
 * 
 *  @param keyNF a tuple of 5 values which collects packets of same values
 *  @param info a info which is assigned to a flow
 *  @param currentTime
 */
void storePacket(tuple<string, string, int, int, string>keyNF, flowInfo info, timeval ts) {

    bool toRecord = true; // indicates if we are going to create new flow or not

    for (map< tuple<string, string, int, int, string>, flowInfo>::iterator itr = flows.begin(); 
    itr != flows.end(); ++itr) {
        if (itr->first== keyNF) {
            cout << "NOT TO RECORD" << endl;
            flowInfo aux = itr->second;
            aux.numOfPackets = aux.numOfPackets + 1;
            aux.lastPacketTime = (ts.tv_sec * 1000 + (ts.tv_usec + 500)/1000) - (bootTime.tv_sec * 1000 + (bootTime.tv_usec + 500)/1000);
            aux.length = aux.length + info.length;
            aux.ts = ts;
            itr->second = aux;
            toRecord = false;

        }       
    }

    if (toRecord == true) { 
            cout << "TO RECORD" << endl;      
           //cout << " A " << ts.tv_sec * 1000 + (ts.tv_usec + 500)/1000 << endl;
            //cout << ts.tv_sec << endl;
            info.firstPacketTime = (ts.tv_sec * 1000 + (ts.tv_usec + 500)/1000) - (bootTime.tv_sec * 1000 + (bootTime.tv_usec + 500)/1000);
            info.lastPacketTime = (ts.tv_sec * 1000 + (ts.tv_usec + 500)/1000) - (bootTime.tv_sec * 1000 + (bootTime.tv_usec + 500)/1000);
            info.numOfPackets =  1;
            info.ts = ts;
            flows[keyNF] = info;

    }  
}


/**
 * Main function
 * 
 * @param argc an integer that indicates how many arguments were entered on the command line
 * @param argv argument vector - contains the arguments passed to a program through the command line
 */

int main(int argc, char *argv[]) {

    argumentsParsing(argc, argv);

    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];

    // because pcap_open_file's firstPacketTime arguments takes only *char
    // i need to change it from std::string
    int n = args.file.length();
    char file[n + 1];
    strcpy(file, args.file.c_str());

    // open capture file for offline processing
    descr = pcap_open_offline(file, errbuf);
    if (descr == NULL) {
        cout << "ERROR > pcap_open_live() failed: " << errbuf << endl;
        return 1;
    }

    // start packet processing loop, just like live capture
    if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
        cout << "ERROR > pcap_loop() failed: " << pcap_geterr(descr);
        return 1;
    }


     for (map< tuple<string, string, int, int, string>, flowInfo>::iterator itr = flows.begin(); itr != flows.end(); ) {
        exportToCollector(itr->first, itr->second, itr->second.ts);
        flows.erase(itr++);

    }
    
    close(sock);
    cout << "<Capturing successfully finished>" << endl;
    
    return 0;
}

/**
 * When  pcap_loop() is called by the user,
 * the packets are passed to the application by means of this callback.
 * 
 * @param userData user-defined parameter that contains the state of the capture session
 * @param pthdr is the header is the header associated by the caputre to the packet
 * @param packet points to the data of the packet
 */ 
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

    /* Structs for Protocols Headers */
    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    const struct udphdr* udpHeader;
    const struct tcphdr* tcpHeader;
    const struct icmphdr* icmpHeader;

    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];
    char tos[INET_ADDRSTRLEN];
    string prot;
    int tcpFlags = 0x0;
    u_int sourcePort, destPort, sourceMac, destMac;
    u_short toss;
    uint16_t length;
 
    timeval ts = pkthdr->ts; // currentTime

    if (!bootTimeRec) { 
        bootTime = ts; 
        bootTimeRec = true;
    }

    bool finFlag = false;
    bool rstFlag = false;
    
    flowInfo info;

    // parsing ethernet header and checking if it contains an IP header
    ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

        info.length = ntohs(ipHeader->ip_len);
        info.networkIPSrcAddr = ipHeader->ip_src.s_addr;
        info.networkIPDstAddr = ipHeader->ip_dst.s_addr;
        info.tos = ipHeader->ip_tos;
        
        if (ipHeader->ip_p == IPPROTO_TCP) {
            tcpHeader = (tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

            sourcePort = ntohs(tcpHeader->source);
            destPort = ntohs(tcpHeader->dest);

            if (tcpHeader->th_flags & TH_FIN)  { finFlag = true; tcpFlags = tcpFlags || 0x01; }
            if (tcpHeader->th_flags & TH_RST)  { rstFlag = true; tcpFlags = tcpFlags || 0x04; }
            if (tcpHeader->th_flags & TH_ACK)  { tcpFlags = tcpFlags || 0x10; }
            if (tcpHeader->th_flags & TH_SYN)  { tcpFlags = tcpFlags || 0x02; }
            if (tcpHeader->th_flags & TH_PUSH) { tcpFlags = tcpFlags || 0x08; }
            if (tcpHeader->th_flags & TH_URG)  { tcpFlags = tcpFlags || 0x20; }

            info.tcp_flags = info.tcp_flags || tcpFlags;
            
            tuple<string, string, int, int, string>keyNF(sourceIp, destIp, sourcePort, destPort, "TCP" );

            activeTimer(ts);
            inActiveTimer(ts);

            if (flows.size() >= 1000) {
                removeFlow(keyNF);
            }
            
            storePacket(keyNF, info, ts);

            if (finFlag or rstFlag) {
                tuple<string, string, int, int, string>  it;
                map< tuple<string, string, int, int, string>, flowInfo>::iterator itr;
                for (itr = flows.begin(); itr != flows.end();) {
                    if (itr->first == keyNF) {
                        cout << "FIN OR RST Flag Activated" << endl;
                        it = itr->first;
                        exportToCollector(itr->first, itr->second, itr->second.ts);
                        flows.erase(itr++);
                    } else {
                        ++itr;
                    }
                }
            }

        } else if (ipHeader->ip_p == IPPROTO_UDP) {
            udpHeader = (udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

            sourcePort = ntohs(udpHeader->source);
            destPort = ntohs(udpHeader->dest);

            tuple<string, string, int, int, string>keyNF(sourceIp, destIp, sourcePort, destPort, "UDP");

            //activeTimer(ts);
            //inActiveTimer(ts);

            if (flows.size() >= 1000) {
                    removeFlow(keyNF);
            }
            
            storePacket(keyNF, info, ts);
         
        } else if (ipHeader->ip_p == IPPROTO_ICMP) {
            icmpHeader = (icmphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            
            tuple<string, string, int, int, string>keyNF(sourceIp, destIp, 0, 0, "ICMP");

            activeTimer(ts);
            inActiveTimer(ts);

            if (flows.size() >= 1000) {
                    removeFlow(keyNF);
            }
            storePacket(keyNF, info, ts);
      }
  }
    
}