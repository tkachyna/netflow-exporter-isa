#include <iostream>
#include <getopt.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <map>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <tuple>


using namespace std;

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

void activeTimer();

void inActiveTimer();

string getIPAddrFromName();

typedef struct Flow {
    int firstPacket;
    int lastPacket;
} Flow;

int j = 0;

int currentTime = 0;

typedef struct packetsInfo {
    int Last = 2; 
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
map<tuple<int, string>, packetsInfo> record;

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

int main(int argc, char *argv[]) {

    Args args;
    string IPAddr;
    int option_index = 0;
    char *user_name = NULL;
    while(( option_index = getopt(argc, argv, "f:c:a:i:m")) != -1) {
        switch(option_index) {
            case 'f':
                args.file = optarg;
                break;
            case 'c':
                IPAddr = getIPAddrFromName(optarg);
                args.ipAddress = IPAddr;
                break;
            case 'a':
                args.activeTimer = stoi(optarg);
                break;
            case 'i':
                args.inactiveTimer =  stoi(optarg);
                break;
            case 'm':
                args.flowCache =  stoi(optarg);
                break;
            default:
                printf("test2");
        }
    }

    /*
    pcap_t *descr;
    char errbuf[1000];
    descr = pcap_open_offline("test.pcap", errbuf);
    if (descr == NULL) {
        printf("Error > pcap_open_offline() failed: %s\n", errbuf);
    }

    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    const struct tcphdr* tcpHeader;
    char sourceIp[1000];
    char destIp[1000];
    u_int sourcePort, destPort;
    u_char *data;
    int dataLengt = 0;
    const u_char* packet;

    ethernetHeader = (struct ether_header*)packet;
    cout << &ethernetHeader;*/
    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];

    // open capture file for offline processing
    descr = pcap_open_offline(args.file, errbuf);
    if (descr == NULL) {
        cout << "pcap_open_live() failed: " << errbuf << endl;
        return 1;
    }

      // start packet processing loop, just like live capture
    if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
        cout << "pcap_loop() failed: " << pcap_geterr(descr);
        return 1;
    }
//162.159.136.234:443 -> 192.168.1.107:52845
  

    cout << "capture finished" << endl;
    
    int test = record.begin()->second.Last;
    //cout << test << endl;
    /*
    for (map< tuple<int, string>, packetsInfo>::iterator itr = record.begin(); itr != record.end(); ++itr) {
        cout << "1" << endl;
        //cout << itr->second << endl;
        (*itr).second = itr->second;
    }*/


    return 0;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  const struct ether_header* ethernetHeader;
  const struct ip* ipHeader;
  const struct tcphdr* tcpHeader;
  char sourceIp[INET_ADDRSTRLEN];
  char destIp[INET_ADDRSTRLEN];
  char tos[INET_ADDRSTRLEN];
  u_int sourcePort, destPort;
  u_int sourceMac, destMac;
  u_char *data;
  u_char prot[100];
  int dataLength = 0;
  string dataStr = "";
  short int vek;
    
  timeval kokotina_vyjebana = pkthdr->ts;
  //cout << kokotina_vyjebana .tv_sec << endl;
  currentTime = kokotina_vyjebana.tv_sec;



  tuple <short int> person(10);
  tie(vek) = person;
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

          // convert non-printable characters, other than carriage return, line feed,
          // or tab into periods when displayed.
          for (int i = 0; i < dataLength; i++) {
              if ((data[i] >= 32 && data[i] <= 126) || data[i] == 10 || data[i] == 11 || data[i] == 13) {
                  dataStr += (char)data[i];
              } else {
                  dataStr += ".";
              }
          }

            tuple<int, string>keyNF(j+1, "TCP");
          packetsInfo info;
         // cout << "hodnota j:" << j << endl;
          if (j == 1) {
           // cout << sourceIp << "test" << endl;
            info.Last = 4;
          }

          record[keyNF] = info;
          j = j + 1;
        //macout << sourceIp << ":" << sourcePort << " -> " << destIp << ":" << destPort << endl;
          //tuple <string, string, int, int, string> keyNF(sourceIp, destIp, sourcePort, destPort, "TCP");
          //cout << get<0>(keyNF) << endl;


      } else if (ipHeader->ip_p == IPPROTO_UDP) {
         cout << "udp" << endl;
      } else if (ipHeader->ip_p == IPPROTO_ICMP) {
         cout << "icmp" << endl;
      }
  }
    



}