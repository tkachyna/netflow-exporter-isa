/**
 *  ===================================================================================
 * 
 *  ISA Project - Implementation of NetFlow exporer
 *  @author Tadeas Kachyna <xkachy00@fit.vutbr.cz>
 *  @date 14.11.2022
 *  @file flow.hpp
 * 
 *  @brief Implementation of NetFlow protocol which is used to monitor
 *   network flow for understanding network patterns and protocol distribution
 *  
 * ====================================================================================
 */

#include<iostream>
#include<getopt.h>
#include<pcap/pcap.h>
#include<net/ethernet.h>
#include<map>
#include<netinet/ip_icmp.h>
#include<netinet/ip.h>
#include<netinet/in.h>
#define __FAVOR_BSD
#include<netinet/udp.h>
#define __FAVOR_BSD
#include<netinet/tcp.h>
#include<arpa/inet.h>
#include<tuple>
#include"arguments.hpp"
#include"client.hpp"

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
    int tcp_flags = 0;
    int label = 1;
} flowInfo;


struct NetFlowV5Packet {
        uint16_t version = htons(5);
        uint16_t count = htons(1);
        uint32_t SysUptime;
        uint32_t unix_secs;
        uint32_t unix_nsecs;
        uint32_t flow_sequence;
        uint8_t engine_type = 0;
        uint8_t engine_id = 0;
        uint16_t sampling_interval = htons(0);
        uint32_t srcaddr;
        uint32_t destaddr;
        uint32_t nexthop = htonl(0);
        uint16_t input = htons(0);
        uint16_t output = htons(0);
        uint32_t dPkts;
        uint32_t length;
        uint32_t First;
        uint32_t Last;
        uint16_t srcport;
        uint16_t dstport;
        uint8_t pad1 = htons(0);
        uint8_t tcp_flags = 0;
        uint8_t prot;
        uint8_t tos;
        uint16_t src_as = htons(0);
        uint16_t dst_as = htons(0);
        uint8_t src_mask = htons(0);
        uint8_t dst_mask = htons(0);
        uint16_t pad2 = htons(0);
    };

void exportToCollector(tuple<string,string,int,int,int,int>NF, flowInfo info, timeval ts);

void checkFlags(tuple<string,string,int,int,int,int>keyNF);

long countMiliseconds(timeval ts);

void activeTimer(timeval ts);

void inActiveTimer(timeval ts);

void storePacket(tuple<string, string, int, int, int, int>keyNF, flowInfo info, timeval ts);

void packetParser(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

