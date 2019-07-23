#ifndef OPEN_FLOW_HELPER
#define OPEN_FLOW_HELPER
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/queue.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <sys/time.h>
#include <math.h>
#include <time.h>

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_mempool.h>
#include <rte_cycles.h>
#include <rte_tcp.h>
#include <rte_ether.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "lteCore.h"
#include "openflow.h"

//#define OF_CLIENT_IP (IPv4(10,10,2,3))
//#define OF_SERVER_IP (IPv4(10,10,2,4))

#define OF_CLIENT_IP (IPv4(10,4,0,13))
#define OF_SERVER_IP (IPv4(10,4,0,12))



struct tcp_packet {
  struct ether_hdr pkt_eth_hdr;
  struct ipv4_hdr pkt_ip_hdr;
  struct tcp_hdr pkt_tcp_hdr;
};
struct tcp_mss_option {
  uint8_t kind;
  uint8_t length;
  uint16_t value;
};
 struct rte_mbuf * make_default_packet (void);
 int handleOfPackets (struct rte_mbuf* pkt, struct onvm_pkt_meta* meta);
 void makeOfConnection (void);
 void sendPacketIn( void* data_to_send, uint16_t data_size);

#endif //OPEN_FLOW_HELPER
