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

#include<iostream>
#include<getopt.h>
#include<string.h>
#include<pcap/pcap.h>
#include<net/ethernet.h>
#include<map>
#include<unistd.h>
#include<netdb.h>
#include<err.h>
#include<netinet/ip_icmp.h>
#include<netinet/ip.h>
#include<netinet/in.h>
#define __FAVOR_BSD
#include<netinet/udp.h>
#define __FAVOR_BSD
#include<netinet/tcp.h>
#include<arpa/inet.h>
#include<tuple>
#include<bits/stdc++.h>
#include"flow.hpp"
using namespace std;

#define ICMP_SRC_PORT 0
#define FLOWSMAP map< tuple<string, string, int, int, int, int>, flowInfo>
#define UNUSED(x) (void)(x)

int sock; // socket descriptor 
int packet = 1; // packet counter (debug)
int exportedFlows = 1; // counter of exported flows (debug)
int flow = 1; // counter of flows (debug)
int flowSequence = 1; // (debug)
uint32_t unix_nsecs;
timeval bootTime;
bool bootTimeRec = false;

map<tuple<string, string, int, int, int, int>, flowInfo> flows; // flow cache
Arguments args; // program arguments

void exportToCollector(tuple<string,string,int,int,int,int>NF, flowInfo info, timeval ts) {

    NetFlowV5Packet packet;

    /// calculate SysUptime
    int32_t SysUptime = (ts.tv_sec * 1000 + (ts.tv_usec + 500)/1000) - (bootTime.tv_sec * 1000 + (bootTime.tv_usec + 500)/1000);

    packet.SysUptime =  htonl(SysUptime);
    packet.unix_secs = htonl(ts.tv_sec);
    packet.unix_nsecs  =  htonl(ts.tv_usec * 1000);
    packet.flow_sequence =  htonl(flowSequence);
    packet.srcaddr =  info.networkIPSrcAddr;
    packet.destaddr = info.networkIPDstAddr;
    packet.dPkts = htonl(info.numOfPackets);
    packet.length = htonl(info.length);
    packet.First =  htonl(info.firstPacketTime);
    packet.Last =  htonl(info.lastPacketTime);
    packet.srcport = htons(get<2>(NF));
    packet.dstport = htons(get<3>(NF));
    packet.tcp_flags = info.tcp_flags;
    packet.prot = get<4>(NF);
    packet.tos = get<5>(NF);

    flowSequence++;
    exportedFlows++;

    int i = send(sock, &packet ,sizeof(NetFlowV5Packet), 0);     // send data to the server
    if (i == -1)                   // check if data was sent correctly
      err(1,"send() failed");

    cout << "Packet successfully sent." << endl;
}   

void removeFlow() {
    FLOWSMAP::iterator itr;
    FLOWSMAP::iterator oldest = flows.begin();

    for (itr = flows.begin(); itr != flows.end(); itr++ ) {
        if(itr->second.firstPacketTime < oldest->second.firstPacketTime) {
            oldest = itr;
        }
    }

    exportToCollector(oldest->first, oldest->second, oldest->second.ts);

    flows.erase(oldest->first);
}


long countMiliseconds(timeval ts) {
    long time = (ts.tv_sec * 1000 + (ts.tv_usec + 500)/1000) - (bootTime.tv_sec * 1000 + (bootTime.tv_usec + 500)/1000);

    return time;
}


/**
 *  Interval in seconds after which active records are exported to the collector.
 * 
 *  @param ts timeval structure with current time 
 */
void activeTimer(timeval ts) {

    FLOWSMAP::iterator itr;
    for ( itr = flows.begin(); itr != flows.end(); ) {
        long firstPacketTime = itr->second.firstPacketTime;
        long currentTime = countMiliseconds(ts);
        long timer = currentTime - firstPacketTime;

        if (timer > args.activeTimer) {
            exportToCollector(itr->first, itr->second, itr->second.ts);
            flows.erase(itr++);

        } else {
            itr++;
        }
    }
}


/**
 *  Interval in seconds after which inactive records are exported to the collector
 * 
 *  @param ts timeval structure with current time
 */
void inActiveTimer(timeval ts) {

    FLOWSMAP::iterator itr;
    for (itr = flows.begin(); itr != flows.end();) {
        long lastPacketTime = itr->second.lastPacketTime;
        long currentTime = countMiliseconds(ts);     
        long timer = currentTime - lastPacketTime;

        if (timer > args.inactiveTimer) {
            exportToCollector(itr->first, itr->second, itr->second.ts);
            flows.erase(itr++);  

        } else {
            ++itr;
        }
    }
}


/**
 *  Create new flow, if one with the key already exists,
 *  find it and agregate values.
 * 
 *  @param keyNF a tuple of 6 values which collects packets of same values
 *  @param info a info which is assigned to a flow
 *  @param ts timeval structure with current time
 */
void storePacket(tuple<string, string, int, int, int, int>keyNF, flowInfo info, timeval ts) {

    bool toRecord = true; // indicates if we are going to create new flow or not

    for (FLOWSMAP::iterator itr = flows.begin(); 
        itr != flows.end(); ++itr) {

        if (itr->first== keyNF) {

            flowInfo aux = itr->second;
            aux.numOfPackets += 1;
            aux.lastPacketTime = countMiliseconds(ts);
            aux.length = aux.length + info.length;
            aux.ts = ts;
            itr->second = aux;
            toRecord = false;
            packet++;
        }       
    }

    if (toRecord == true) { 

        info.firstPacketTime = countMiliseconds(ts);
        info.lastPacketTime = info.firstPacketTime;
        info.numOfPackets =  1;
        info.ts = ts;
        info.label = flow;
        flows[keyNF] = info;
        flow++;
        packet++;
    }  
}


/**
 * Main function
 * 
 * @param argc an integer that indicates how many arguments were entered on the command line
 * @param argv argument vector - contains the arguments passed to a program through the command line
 */

int main(int argc, char *argv[]) {

    exportedFlows = 0;

    args = argumentsParsing(argc, argv, args);

    sock = setUDPClient(args.ipAddress, args.port);

    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];

    // because pcap_open_file's firstPacketTime arguments takes only *char
    // i need to change it from std::string
    int n = args.file.length();
    char *file = new char[n + 1];
    strcpy(file, args.file.c_str());

    // open capture file for offline processing
    descr = pcap_open_offline(file, errbuf);
    if (descr == NULL) {
        cout << "ERROR >> pcap_open_live() failed: " << errbuf << endl;
        return 1;
    }

    // start packet processing loop, just like live capture
    if (pcap_loop(descr, 0, packetParser, NULL) < 0) {
        cout << "ERROR >> pcap_loop() failed: " << pcap_geterr(descr);
        return 1;
    }

    // exporting rest of the flows which remained in the cache
    for (FLOWSMAP::iterator itr = flows.begin(); itr != flows.end(); ) {
        exportToCollector(itr->first, itr->second, itr->second.ts);
        flows.erase(itr++);
    }

    close(sock);
    delete file;

    cout << ">> Total number of exported flows: " << exportedFlows << endl;
    cout << ">> Capturing successfully finished." << endl;

    return 0;
}


/**
 * When pcap_loop() is called
 * the packets are passed to the application by means of this callback.
 * 
 * @param data user-defined parameter that contains the state of the capture session
 * @param pkthdr is the header is the header associated by the capture to the packet
 * @param packet points to the data of the packet
 */ 
void packetParser(u_char *data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

    UNUSED(data); // suppress warning unused parameter

    /* Structs for Protocols Headers */
    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    const struct udphdr* udpHeader;
    const struct tcphdr* tcpHeader;
    const struct icmphdr* icmpHeader;

    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];
    u_int sourcePort, destPort;
    uint8_t typeOfService;
    bool finFlag = false;
    bool rstFlag = false;

    flowInfo info;
    timeval ts = pkthdr->ts; // currentTime

    if (!bootTimeRec) { // set up the boot time
        bootTime = ts; 
        bootTimeRec = true;
    }

    // parsing ethernet header and checking if it contains an IP header
    ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        
        // transfering ip adresseses to more human readable format
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

        info.networkIPSrcAddr = ipHeader->ip_src.s_addr;
        info.networkIPDstAddr = ipHeader->ip_dst.s_addr;
        info.length = ntohs(ipHeader->ip_len);
        typeOfService = ipHeader->ip_tos;

        if (ipHeader->ip_p == IPPROTO_TCP) {
            tcpHeader = (tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

            sourcePort = ntohs(tcpHeader->th_sport);
            destPort = ntohs(tcpHeader->th_dport);

            tuple<string, string, int, int, int, int>keyNF
            (
                sourceIp, destIp, sourcePort, destPort, IPPROTO_TCP, typeOfService
            );
            
            // checking the presence of TCP flags FIN and RST
            if (tcpHeader->th_flags & TH_FIN)  { 
                finFlag = true; 
            }

            if (tcpHeader->th_flags & TH_RST)  {
                rstFlag = true; 
            }

            info.tcp_flags = tcpHeader->th_flags;

            inActiveTimer(ts);
            activeTimer(ts);

            if (flows.size() > args.flowCache) { // checking flow cache size
                removeFlow(); 
            } 

            storePacket(keyNF, info, ts);

            if (finFlag or rstFlag) { // FIN or RST is present
                for (FLOWSMAP::iterator itr = flows.begin(); itr != flows.end();) {
                    if (itr->first == keyNF) {
                        exportToCollector(itr->first, itr->second, itr->second.ts);
                        flows.erase(itr++);

                    } else {
                        ++itr;

                    }
                }
            }

        } else if (ipHeader->ip_p == IPPROTO_UDP) {
            udpHeader = (udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

            sourcePort = ntohs(udpHeader->uh_sport);
            destPort = ntohs(udpHeader->uh_dport);

            tuple<string, string, int, int, int, int>keyNF
            (
                sourceIp, destIp, sourcePort, destPort, IPPROTO_UDP, typeOfService
            );

            inActiveTimer(ts);
            activeTimer(ts);

            if (flows.size() > args.flowCache) { 
                removeFlow(); 
            }

            storePacket(keyNF, info, ts);

        } else if (ipHeader->ip_p == IPPROTO_ICMP) {
            icmpHeader = (icmphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

            u_int type = icmpHeader->type;
            u_int code = icmpHeader->code;
            sourcePort = ICMP_SRC_PORT;
            destPort = (type << 8) + code;

            tuple<string, string, int, int, int, int>keyNF
            (
                sourceIp, destIp, sourcePort, destPort, IPPROTO_ICMP, typeOfService
            );

            inActiveTimer(ts);
            activeTimer(ts);

            if (flows.size() > args.flowCache) { 
                removeFlow(); 
            }

            storePacket(keyNF, info, ts); 
        }  
    } 
}
