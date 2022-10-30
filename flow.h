#include <iostream>
#include <getopt.h>
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

#include "netflowprot.h"
#include "udp-client.h"