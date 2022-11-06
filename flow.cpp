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
#include<unistd.h>
#include<netdb.h>
#include<err.h>
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

uint32_t bootTime;
uint32_t unix_nsecs;
int flowSequence = 1;

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

void activeTimer(int currentTime);

void inActiveTimer(int currentTime);

void checkFlowChache();


string getIPAddrFromName();

typedef struct currentlyProcessedPacketInfo {
    uint16_t totLen;
    uint8_t tos;

} currentlyProcessedPacketInfo;

int j = 0;



typedef struct packetsInfo {
    long First = 0;
    long Last = 0; 
    int dPkts = 0;
    int dOctets = 0;
    int tcp_flags = 0;
    int prot = 0;
} packetsInfo;

typedef struct Arguments {
    char file[100];
    string ipAddress = "127.0.0.1:2055";
    int activeTimer = 60;
    int inactiveTimer = 10;
    int flowCache = 1024;
} Args;

Args args;

map<tuple<string, string, int, int, string>, packetsInfo> flows;

string getIPAddrFromName(char *inputName) {

    string IPAddr;
    cout << inputName << endl;
    struct hostent *hostName = gethostbyname(inputName);
    if (hostName) {
        IPAddr = inet_ntoa(*((struct in_addr*) hostName->h_addr_list[0])); 
        cout << IPAddr << endl;
    } else {
        return inputName;
    }    
    return IPAddr;
}

/**
 * setUDPClient
 * 
 * @brief Simple echo connected UDP client with two parameters and the connect() function
 * @author Petr Matousek, 2016, Last Updated 2019
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

    if ((servent = gethostbyname("127.0.0.1")) == NULL) // check the first parameter
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

void exportToCollector(tuple<string,string,int,int,string>NF, packetsInfo info, uint32_t currentTime) {

    
    int sock = setUDPClient();
    long i;
    NFv5_header header;
    NFv5_body body;

    



    // converting ipv4 adress to network adress
    int lenSrcAddr = get<0>(NF).length();
    int lenDestAddr = get<1>(NF).length();

    char srcAddr[lenSrcAddr];
    char dstAddr[lenDestAddr];

    unsigned char buf[sizeof(struct in_addr)];
    strcpy(srcAddr, get<0>(NF).c_str());
    strcpy(dstAddr, get<1>(NF).c_str()); 
    cout << " ================== This Flow is beeing exported ==============================" << endl;
    cout << " Src Address: " << srcAddr << endl;
    cout << "Dest Address: " << dstAddr << endl;
    cout << "    Src Port: " << get<2>(NF) << endl;
    cout << "    DestPort: " << get<3>(NF) << endl;
    cout << "       First: " << info.First << endl;
    cout << "        Last: " << info.Last  << endl;
    cout << "       dPkts: " << info.dPkts << endl;
    cout << "     dOctets: " << info.dOctets  << endl;
    cout << " ================================== End =======================================" << endl;
     /// calculate SysUptime
    uint32_t SysUptime = bootTime - currentTime;

    struct NetFlowV5Packet {
        uint16_t version;
        uint16_t count;
        uint32_t SysUptime;
        uint32_t unix_secs;
        uint32_t unix_nsecs;
        uint32_t flow_sequence;
        uint8_t engine_type;
        uint8_t engine_id;
        uint16_t sampling_interval;
        uint32_t srcaddr;
        uint32_t destaddr;
        uint32_t nexthop;
        uint16_t input;
        uint16_t output;
        uint32_t dPkts;
        uint32_t dOctets;
        uint32_t First;
        uint32_t Last;
        uint16_t srcport;
        uint16_t dstport;
        uint8_t pad1;
        uint8_t tcp_flags;
        uint8_t prot;
        uint8_t tos;
        uint16_t src_as;
        uint16_t dst_as;
        uint8_t src_mask;
        uint8_t dst_mask;
        uint16_t pad2;
    };

    NetFlowV5Packet packet;
    packet.version = htons(5);
    packet.count = htons(1);
    packet.SysUptime =  htonl(SysUptime);
    packet.unix_secs = htonl(currentTime);
    packet.unix_nsecs  = htonl(1000);
    packet.flow_sequence =  htonl(flowSequence);
    packet.engine_type = 0;
    packet.engine_id = 0;
    packet.sampling_interval = htons(0);
    packet.srcaddr = htonl(inet_pton(AF_INET, srcAddr, buf));
    packet.destaddr = htonl(inet_pton(AF_INET, dstAddr, buf));
    packet.nexthop = htonl(0);
    packet.input = htons(0);
    packet.output = htons(0);
    packet.dPkts = htons(info.dPkts);
    packet.dOctets = htons(info.dOctets);
    packet.First = htons(info.First);
    packet.Last = htons(info.Last);
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

    close(sock);
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

void activeTimer(long currentTime) {
     
     int firstPacketTime;
     for (map< tuple<string, string, int, int, string>, packetsInfo>::iterator itr = flows.begin(); itr != flows.end(); ) {
        firstPacketTime = itr->second.First;
        if (currentTime - firstPacketTime > 60) {
            cout << "Active Timer Activated" << endl;
            exportToCollector(itr->first, itr->second, itr->second.Last);
            flows.erase(itr++);
        } else {
            itr++;
        }
    }
}

void inActiveTimer(long currentTime) {
    
    int lastPacketTime;
    tuple<string, string, int, int, string>  it;
    map< tuple<string, string, int, int, string>, packetsInfo>::iterator itr;
    for (itr = flows.begin(); itr != flows.end();) {
        if (currentTime - itr->second.Last > 10) {
            it = itr->first;
            cout << "Inactive Timer Activated" << endl;
            cout << "Removing flow ... " << get<0>(itr->first) << " : " << get<1>(itr->first) << " : " << get<2>(itr->first) << " : " << get<3>(itr->first) << " : " << get<4>(itr->first) << endl;
            exportToCollector(itr->first, itr->second, itr->second.Last);
            //removeFlow(itr->first, itr);
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
                strcpy(args.file, optarg);
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
            default:
                printf("test2");
        }
    }
}

/**
 *  Create new flow, if one with the key already exists,
 *  find it and agregate values
 * 
 *  @param keyNF a tuple of 5 values which collects packets of same values
 *  @param info a info which is assigned to a flow
 */
void storePacket(tuple<string, string, int, int, string>keyNF, packetsInfo info, long currentTime) {

    bool toRecord = true; // indicates if we are going to create new flow or not

    cout << currentTime << endl;
    for (map< tuple<string, string, int, int, string>, packetsInfo>::iterator itr = flows.begin(); itr != flows.end(); ++itr) {

        if (itr->first == keyNF) {
            packetsInfo aux = itr->second;
            aux.dPkts = aux.dPkts + 1;
            aux.Last = currentTime;
            itr->second = aux;
            toRecord = false;
        }

        /*
        cout << "(" << get<0>(itr->first) 
        << ", " << get<1>(itr->first)
        << ", " << get<2>(itr->first) 
        << ", " << get<3>(itr->first) 
        << ", " << get<4>(itr->first) 
        << ")" 
        << "NumOfPakets: " << itr->second.dPkts 
        << " /FirstP: " << itr->second.First  
        << " /LastP: " << itr->second.Last 
        << "\n";*/
       // cout << itr->second.Last << endl;       
    }

    if (toRecord == true) {
            
            info.First = currentTime;
            info.Last = currentTime;
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

    // open capture file for offline processing
    descr = pcap_open_offline("test.pcap", errbuf);
    if (descr == NULL) {
        cout << "pcap_open_live() failed: " << errbuf << endl;
        return 1;
    }

    // start packet processing loop, just like live capture
    if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
        cout << "pcap_loop() failed: " << pcap_geterr(descr);
        return 1;
    }
  
    cout << "Capturing finished." << endl;
    
    return 0;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

    /* Structs for Protocols Headers */
    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    const struct iphdr* ipHdr;
    const struct udphdr* udpHeader;
    const struct tcphdr* tcpHeader;
    const struct icmphdr* icmpHeader;

    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];
    char tos[INET_ADDRSTRLEN];
    u_int sourcePort, destPort, sourceMac, destMac;
    string prot;
    int dataLength = 0;
    string dataStr = "";
    int checksum;
    u_int16_t length;
    u_short toss;
    bool finFlag = false;
    bool rstFlag = false;
    int tcpFlags = 0x0;
 
    packetsInfo info;
    currentlyProcessedPacketInfo packetInfo;

    long currentTime = pkthdr->ts.tv_sec;
    unix_nsecs = pkthdr->ts.tv_usec;

    ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        ipHdr = (struct iphdr*)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);
        length = ntohs(ipHdr->tot_len);
        toss = ipHdr->tos;
     

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

            activeTimer(currentTime);
            inActiveTimer(currentTime);

            if (flows.size() >= 1000) {
                removeFlow(keyNF);
            }
            
            storePacket(keyNF, info, currentTime);

            if (finFlag or rstFlag) {
                tuple<string, string, int, int, string>  it;
                map< tuple<string, string, int, int, string>, packetsInfo>::iterator itr;
                for (itr = flows.begin(); itr != flows.end();) {
                    if (itr->first == keyNF) {
                        it = itr->first;
                        cout << "FIN OR RST Flag Activated" << endl;
                        exportToCollector(itr->first, itr->second, itr->second.Last);
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

            activeTimer(currentTime);
            inActiveTimer(currentTime);

            if (flows.size() >= 1000) {
                    removeFlow(keyNF);
            }
            
            storePacket(keyNF, info, currentTime);
         
        } else if (ipHeader->ip_p == IPPROTO_ICMP) {

            icmpHeader = (icmphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            
            tuple<string, string, int, int, string>keyNF(sourceIp, destIp, 0, 0, "ICMP");

            activeTimer(currentTime);
            inActiveTimer(currentTime);

            if (flows.size() >= 1000) {
                    removeFlow(keyNF);
            }
            storePacket(keyNF, info, currentTime);

      }
  }
    
}