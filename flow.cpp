#define __FAVOR_BSD

#include <iostream>
#include <getopt.h>
#include <string.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <map>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <tuple>
#include "flow.h"

using namespace std;

uint32_t bootTime;

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

void activeTimer(int currentTime);

void inActiveTimer(int currentTime);

void checkFlowChache();


string getIPAddrFromName();

typedef struct Flow {
    int firstPacket;
    int lastPacket;
} Flow;

int j = 0;

int currentTime = 0;

typedef struct packetsInfo {
    int First = 1;
    int Last = 1; 
    int dPkts = 1;
    int dOctets = 1;
    int tcp_flags = 1;
} packetsInfo;

typedef struct Arguments {
    char *file;
    string ipAddress = "127.0.0.1:2055";
    int activeTimer = 60;
    int inactiveTimer = 10;
    int flowCache = 1024;
} Args;

map<int, Flow> flow;
map<tuple<string, string, int, int, string>, packetsInfo> record;

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

void exportToCollector(tuple<string,string,int,int,string>NF, packetsInfo info) {
    //cout << "Exporting to collector ..." << endl;
    NetFlowV5header header;
    NetFlowv5flowrecord body;

    header.version = 5;
    header.count = 1;
    header.SysUptime = 0;
    header.unix_secs = 0;
    header.unix_nsecs = 0;
    header.flow_sequence = 0;
    header.engine_type = 0;
    header.engine_id = 0;
    header.sampling_interval = 0;

    body.srcaddr = get<0>(NF);
    body.destaddr = get<1>(NF);
    body.nexthop = 0;
    body.input = 0;
    body.output = 0;
    body.dPkts = info.dPkts;
    body.dOctets = info.dOctets;
    body.First = info.First;
    body.Last = info.Last;
    body.srcport = get<2>(NF);
    body.dstport = get<3>(NF);
    body.prot = 0;
    body.tos = 0;
    body.src_as = 0;
    body.dst_as = 0;
    body.src_mask = 32;
    body.dst_mask = 32;
    body.pad2 = 0;


    header.version = htons(header.version);
    header.count = htons(1);
    header.SysUptime = htons(0);
    header.unix_secs = htons(0);
    header.unix_nsecs = htons(0);
    header.flow_sequence = htons(0);
    header.engine_type = htons(0);
    header.engine_id = htons(0);
    header.sampling_interval = htons(0);

    body.nexthop = htons(body.nexthop);
    body.input = htons(body.input);
    body.output = htons(body.output);
    body.dPkts = htons(body.dPkts);
    body.dOctets = htons(body.dOctets);
    body.First = htons(body.First);
    body.Last = htons(body.Last);
    body.srcport =  htons(body.srcport);
    body.dstport =  htons(body.dstport);
    body.prot =  htons(0);
    body.tos =  htons(0);
    body.src_as =  htons(0);
    body.dst_as =  htons(0);
    body.src_mask =  htons(32);
    body.dst_mask =  htons(32);
    body.pad2 =  htons(0);

    /*
    * long i = send(udp->sock, buffer, sizeof(buffer), 0);
    * a buffer su len naparsovane data z NF struktury
    * cez memcpy
    *
    * i ta struktura se tam asi dá jebnout
    * 
    * no tak das cez memcpy header do bufferu, posinies pointer o velkost headeru a das telo
    */

   
}



void removeFlow(tuple<string, string, int, int, string>keyNF) {
    cout << "Removing flow ... " << get<0>(keyNF) << " : " << get<1>(keyNF) << " : " << get<2>(keyNF) << " : " << get<3>(keyNF) << " : " << get<4>(keyNF) << endl;
    record.erase(keyNF);
    cout << "test2" << endl;
}

void checkFlowCache() {
    if (record.size() == 1024) {
        record.erase(record.begin());
    }
}

void activeTimer(int currentTime) {
     
     int firstPacketTime;
     for (map< tuple<string, string, int, int, string>, packetsInfo>::iterator itr = record.begin(); itr != record.end(); ) {
        firstPacketTime = itr->second.First;
        if (currentTime - firstPacketTime > 60) {
            exportToCollector(itr->first, itr->second);
            removeFlow(itr->first);
        } else {
            itr++;
        }
    }
}

void inActiveTimer(int currentTime) {
    
    int lastPacketTime;
    tuple<string, string, int, int, string>  it;
    map< tuple<string, string, int, int, string>, packetsInfo>::iterator itr;
    for (itr = record.begin(); itr != record.end();) {
        if (currentTime - itr->second.Last > 10) {
            it = itr->first;
            cout << "Removing flow ... " << get<0>(itr->first) << " : " << get<1>(itr->first) << " : " << get<2>(itr->first) << " : " << get<3>(itr->first) << " : " << get<4>(itr->first) << endl;
            //exportToCollector(itr->first, itr->second);
            //removeFlow(itr->first, itr);
            //cout << "Removing flow ... " << get<0>(itr->firs) << " : " << get<1>(keyNF) << " : " << get<2>(keyNF) << " : " << get<3>(keyNF) << " : " << get<4>(keyNF) << endl;
            record.erase(itr++);
            cout << "test 3 " << endl;
       
        } else {
            ++itr;
        }

    }


}

/**
 * Parse arguments
 * 
 * @param argc an integer that indicates how many arguments were entered on the command line
 * @param argv argument vector - contains the arguments passed to a program through the command line
*/
void argumentsParsing(int argc, char *argv[]) {
    Args args;
    string IPAddr;
    int option_index = 0;
    while(( option_index = getopt(argc, argv, "f:c:a:i:m")) != -1) {
        switch(option_index) {
            case 'f': // parsed file name or STDIN
                break; 
            case 'c': // IP Adress or hostname of the collector
                IPAddr = getIPAddrFromName(optarg);
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
void createNewFlow(tuple<string, string, int, int, string>keyNF, packetsInfo info) {

    bool toRecord = true; // indicates if we are going to create new flow or not

     
    for (map< tuple<string, string, int, int, string>, packetsInfo>::iterator itr = record.begin(); itr != record.end(); ++itr) {

        if (itr->first == keyNF) {
            packetsInfo aux = itr->second;
            aux.dPkts = aux.dPkts + 1;
            aux.Last = currentTime;
            itr->second = aux;
            toRecord = false;
        }

        cout << "(" << get<0>(itr->first) 
        << ", " << get<1>(itr->first)
        << ", " << get<2>(itr->first) 
        << ", " << get<3>(itr->first) 
        << ", " << get<4>(itr->first) 
        << ")" 
        << "NumOfPakets: " << itr->second.dPkts 
        << " /FirstP: " << itr->second.First  
        << " /LastP: " << itr->second.Last 
        << "\n";
       // cout << itr->second.Last << endl;       
    }

    if (toRecord == true) {
            info.First = info.Last = currentTime;
            record[keyNF] = info;
    }  
}



int main(int argc, char *argv[]) {

    argumentsParsing(argc, argv);
   // udpclient(argc, argv);

    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];

    // open capture file for offline processing
    descr = pcap_open_offline("icmp.pcap", errbuf);
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
    const struct udphdr* udpHeader;
    const struct tcphdr* tcpHeader;
    const struct icmphdr* icmpHeader;

    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];
    char tos[INET_ADDRSTRLEN];
    u_int sourcePort, destPort;
    u_int sourceMac, destMac;
    string prot;
    u_char *data;
    int dataLength = 0;
    string dataStr = "";
    int checksum;
    bool finFlag = false;
    bool rstFlag = false;
 
    packetsInfo info;
    
    currentTime = pkthdr->ts.tv_sec;

    ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
      
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

        if (ipHeader->ip_p == IPPROTO_TCP) {

            tcpHeader = (tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            sourcePort = ntohs(tcpHeader->source);
            destPort = ntohs(tcpHeader->dest);
            data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
            dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));

            if (tcpHeader->th_flags & TH_FIN) {

                cout << "FIN FLAG" << endl;
                finFlag = true;
            }
        
            if (tcpHeader->th_flags & TH_RST) {

                cout << "RST FLAG" << endl;
                rstFlag = true;
            }


            tuple<string, string, int, int, string>keyNF(sourceIp, destIp, sourcePort, destPort, "TCP");
            createNewFlow(keyNF, info);

            activeTimer(currentTime);
            inActiveTimer(currentTime);
        

      } else if (ipHeader->ip_p == IPPROTO_UDP) {

        udpHeader = (udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        sourcePort = ntohs(udpHeader->source);
        destPort = ntohs(udpHeader->dest);
        tuple<string, string, int, int, string>keyNF(sourceIp, destIp, sourcePort, destPort, "UDP");
        activeTimer(currentTime);
        inActiveTimer(currentTime);
        cout << " ====== " << endl;
        cout << " >>>>> " << sourceIp << ":" << sourcePort << " -> " << destIp << ":" << destPort << endl;
        createNewFlow(keyNF, info);
       
        

      } else if (ipHeader->ip_p == IPPROTO_ICMP) {

        icmpHeader = (icmphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        tuple<string, string, int, int, string>keyNF(sourceIp, destIp, 0, 0, "ICMP");
        activeTimer(currentTime);
        inActiveTimer(currentTime);
        cout << " ====== " << endl;
        cout << " >>>>> " << sourceIp << ":" << sourcePort << " -> " << destIp << ":" << destPort << endl;
        createNewFlow(keyNF, info);
        // printf("ICMP msgtype=%d, code=%d", icmpHeader->type, icmpHeader->code);
        // cout << "icmp" << endl;

      }
  }
    
}