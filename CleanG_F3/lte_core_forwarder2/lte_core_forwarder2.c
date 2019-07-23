/*                     openNetVM
 *       https://github.com/sdnfv/openNetVM
 *
 *  Copyright 2015 George Washington University
 *            2015 University of California Riverside
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 * monitor.c - an example using onvm. Print a message each p package received
 ********************************************************************/

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

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_malloc.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "lteCore.h"

#define NF_TAG "simple_forward"

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
#include <rte_hash_crc.h>
#define DEFAULT_HASH_FUNC       rte_hash_crc
#else
#include <rte_jhash.h>
#define DEFAULT_HASH_FUNC       rte_jhash
#endif

#if UTILIZATION_LOGGING == ACTIVATED
long long lastRecordedSecond = 0;
//static struct timespec lastStartPeriod;
static struct timespec lastExitTime;
static unsigned long totalActiveTimeInLastPeriod;
//static unsigned long totalIdleTimeInLastPeriod;
// It is is not started with zero. current_time_second % MAXIMUM_RUN_TIME_IN_SECONDS is used for storage
static double utilization [MAXIMUM_RUN_TIME_IN_SECONDS];
#endif
#if ADD_SEQUENCE_NUMBER == ACTIVATED
static uint64_t lastSeqNo = 0;
#endif


/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

/* number of package between each print */
static uint32_t print_delay = 1000000;

static struct rte_hash *encap_hash = NULL;
static uint32_t destination;

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
  critical_print("Usage: %s [EAL args] -- [NF_LIB args] -- -d <destination> -p <print_delay>\n\n", progname);
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
  int c;
  //corePrint2();
  while ((c = getopt(argc, argv, "d:p:")) != -1) {
    switch (c) {
      case 'd':
	destination = strtoul(optarg, NULL, 10);
	break;
      case 'p':
	print_delay = strtoul(optarg, NULL, 10);
	break;
      case '?':
	usage(progname);
	if (optopt == 'd')
	  RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
	else if (optopt == 'p')
	  RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
	else if (isprint(optopt))
	  RTE_LOG(INFO, APP, "Unknown option `-%c'.\n", optopt);
	else
	  RTE_LOG(INFO, APP, "Unknown option character `\\x%x'.\n", optopt);
	return -1;
      default:
	usage(progname);
	return -1;
    }
  }
  return optind;
}

/*
 * This function displays stats. It uses ANSI terminal codes to clear
 * screen when called. It is called from a single non-master
 * thread in the server process, when the process is run with more
 * than one lcore enabled.
 */
static void
do_stats_display(struct rte_mbuf* pkt) {
  const char clr[] = { 27, '[', '2', 'J', '\0' };
  const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };
  static int pkt_process = 0;
  struct ipv4_hdr* ip;

  pkt_process += print_delay;

  /* Clear screen and move to top left */
  critical_print("%s%s", clr, topLeft);

  critical_pprint("PACKETS\n");
  critical_pprint("-----\n");
  critical_print("Port : %d\n", pkt->port);
  critical_print("Size : %d\n", pkt->pkt_len);
  critical_print("N°   : %d\n", pkt_process);
  critical_pprint("\n\n");

  ip = onvm_pkt_ipv4_hdr(pkt);
  if (ip != NULL) {
    onvm_pkt_print(pkt);
  } else {
    critical_pprint("No IP4 header found\n");
  }
}

static int
packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta, __attribute__((unused)) struct onvm_nf_info *nf_info) {
#if UTILIZATION_LOGGING == ACTIVATED
  struct timespec currentTime;
  clock_gettime(CLOCK_REALTIME, &currentTime);
  if (currentTime.tv_sec - lastRecordedSecond >= 1) {
    lastRecordedSecond = currentTime.tv_sec;
    // There is a trade of in using total idel time. by using total idle time we could double check for correctness, but it
    // so that case had to bahdled separately.
    //    totalIdleTimeInLastPeriod += 1000000000 - lastExitTime.tv_nsec;
    utilization [ currentTime.tv_sec % MAXIMUM_RUN_TIME_IN_SECONDS] = (float) totalActiveTimeInLastPeriod / 1000000000.0f;
    totalActiveTimeInLastPeriod = 0;
    int i = 0;
    for (i = lastExitTime.tv_sec +1; i < currentTime.tv_sec; i++) {
      utilization [ i % MAXIMUM_RUN_TIME_IN_SECONDS] = 0;
    }
  }
  //  else {
  // probably for now nothing need to be done, we are counting the active time of currrent period
  //  }
#endif


  //ali_debug_print("debugtest %i", 11);
  //printf("%i",ALIDEBUG);
  //printf ("print delay %i \n",print_delay);
  if (pkt->port == PORT_TOWARD_OF_SERVER  && SIMULATION_MODE == SDN) {
    struct ipv4_hdr* iph;
    iph = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr*, sizeof(struct ether_hdr));
    if (iph->dst_addr == rte_be_to_cpu_32(IPv4(10,10,2,2))) {
      //printf ("packet goes to 10 10 2 2\n");
      //pgw
      meta->destination = LTE_PGW1_SERVICE_ID;
    }
    else if (iph->dst_addr == rte_be_to_cpu_32(IPv4(10,10,2,3)))
    {
      //printf ("packet goes to 10 10 2 3\n");
      meta->destination = LTE_SGW1_SERVICE_ID;

    }
    else {
      printf ("where does this open flow packet goes??\n");
      meta->action = ONVM_NF_ACTION_DROP;
    } 
    meta->action = ONVM_NF_ACTION_TONF;
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }
  // packet coming back from control part should go to enb
  if (pkt->port == SDN_F3_TOWARD_CONTROL_PORT && SIMULATION_MODE == SDN) {
    printf ("I beleive this run should never run!\n");
    /*
       FILE *fp;
       fp = fopen("dump.txt", "a");
       fprintf (fp, "received packet \n");
       rte_pktmbuf_dump(fp, pkt, pkt->pkt_len);
       fclose(fp);
     */
    ali_debug_pprint ("sending control packet back to enb\n");
#if ADD_SEQUENCE_NUMBER == ACTIVATED
    rte_pktmbuf_adj(pkt, sizeof (struct ether_hdr));
    struct reliabilityLayer *rl = rte_pktmbuf_mtod(pkt, struct reliabilityLayer*);
    if (rl->seqno != lastSeqNo + 1) {
      printf ("sequence no is %lu and last seq no is %lu\n", rl->seqno, lastSeqNo);
    }
    lastSeqNo = rl->seqno;

    rte_pktmbuf_adj(pkt, sizeof (struct reliabilityLayer));
    //prependETHF3toF2SDN(pkt);
    //TODO: Ali following line is added for the sake of testing. it should be removed.
    //rte_pktmbuf_append (pkt, sizeof (struct reliabilityLayer));
    prependETHF4toF32(pkt);
#endif 
    meta->destination  = SDN_F3_TOWARD_ENB_PORT;
    meta->action = ONVM_NF_ACTION_OUT;
    /*
       fp = fopen("dump.txt", "a");
       fprintf (fp, "sent packet \n");
       rte_pktmbuf_dump(fp, pkt, pkt->pkt_len);
       fclose(fp);
     */


#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }

  static uint32_t counter = 0;
  if (++counter == print_delay && SHOW_PACKET_STATS != DISABLED) {
    do_stats_display(pkt);
    counter = 0;
  }
  //check if packet is coming from outside
  struct ether_hdr * eh;
  eh = rte_pktmbuf_mtod (pkt,struct ether_hdr*);
  if ((eh->d_addr.addr_bytes[0] == 140u) && (eh->d_addr.addr_bytes[1] == 220u)
      && (eh->d_addr.addr_bytes[2] == 212u) && (eh->d_addr.addr_bytes[3] == 172u)
      && (eh->d_addr.addr_bytes[4] == 0x6c) && (eh->d_addr.addr_bytes[5] == 0x7c) )       
  {
    ali_debug_pprint("packet received from outside, remove ether header\n");

    struct ipv4_hdr *iph;
    iph = rte_pktmbuf_mtod_offset (pkt,struct ipv4_hdr*, sizeof(struct ether_hdr));

    //check if packet is destined to MME-1
    if (iph->dst_addr  == rte_be_to_cpu_32(MME1IP))
    {
      if (SIMULATION_MODE != SDN) {
	// remove ethernet header
	rte_pktmbuf_adj(pkt, 14);
      } else {
	eh->s_addr.addr_bytes[0] = 0x8c;
	eh->s_addr.addr_bytes[1] = 0xdc;
	eh->s_addr.addr_bytes[2] = 0xd4;
	eh->s_addr.addr_bytes[3] = 0xac;
	eh->s_addr.addr_bytes[4] = 0x6c;
	eh->s_addr.addr_bytes[5] = 0xfd;

	eh->d_addr.addr_bytes[0] = 0x8c;
	eh->d_addr.addr_bytes[1] = 0xdc;
	eh->d_addr.addr_bytes[2] = 0xd4;
	eh->d_addr.addr_bytes[3] = 0xac;
	eh->d_addr.addr_bytes[4] = 0x6b;
	eh->d_addr.addr_bytes[5] = 0x21;

      }

      //critical_print("packet for MME1, normal printf \n");
      ali_debug_pprint ("packet for MME 1/core 1 received\n");
      if (iph->next_proto_id == IP_TYPE_GUSER) {
	ali_debug_pprint("A data packet\n");
	rte_pktmbuf_adj(pkt, 20);

	if ( (counter % 3) == 0) {
	  meta->destination = LTE_REP1_SERVICE_ID;
	} else if (counter % 3 == 1){
	  meta->destination = LTE_REP2_SERVICE_ID;
	} else {
	  meta->destination = LTE_REP3_SERVICE_ID;
	}
      }
      else {
	ali_debug_pprint("A control packet\n");
	meta->destination = LTE_MME1_SERVICE_ID;
      }
      meta->action = ONVM_NF_ACTION_TONF;
      if (SIMULATION_MODE == SDN) {
	meta->destination = SDN_F3_TOWARD_CONTROL_PORT;
	meta->action = ONVM_NF_ACTION_OUT;
      }
#if UTILIZATION_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &lastExitTime);
      totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

      return 0;
    }
    rte_pktmbuf_adj(pkt, 14);
    //check if packet is destined to SGW1
    if (iph->dst_addr  == rte_be_to_cpu_32(SGW1IP))
    {
      //critical_pprint("packet for MME1, normal printf \n");
      ali_debug_pprint ("packet for SGW 1 received\n");
      meta->destination = LTE_SGW1_SERVICE_ID;
      meta->action = ONVM_NF_ACTION_TONF;
#if UTILIZATION_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &lastExitTime);
      totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

      return 0;
    }


  }
  if (pkt->port == DATA_PACKET_PORT) {
    ali_debug_pprint("a data packet heading outside is received\n");
    struct ipv4_hdr *iph = rte_pktmbuf_mtod(pkt, struct ipv4_hdr*);
    uint32_t *enbIP = NULL;
    ali_debug_print("ueIP is %u\n", iph->dst_addr);
    ali_debug_print("ueIP in other format is %u\n", rte_be_to_cpu_32(iph->dst_addr));
    uint32_t ueIP = rte_be_to_cpu_32(iph->dst_addr);
    ali_debug_pprint("before lookup data\n");
    
    //int lookup_code = rte_hash_lookup_data(encap_hash, &(ueIP) ,(void**) &enbIP);
     int lookup_code = rte_hash_lookup_with_hash_data(encap_hash, &(ueIP), MY_HASH_FUNCTION(ueIP), (void**) &enbIP);
    ali_debug_pprint("after lookup data\n");
    uint32_t tempENBIP = ENB1IP;
    ali_debug_print("look up code is %d\n",lookup_code);
    // TODO: It seems the Api's document is not ritht! and this function returns the place in the hash!
    if (lookup_code < 0) {
      critical_pprint("problem in hash table look up!\n");
      critical_print("look up code is: %d \n", lookup_code);
      if (enbIP != NULL) {
	critical_print ("enbIP is %u\n", *enbIP);
      } else {
	critical_pprint ("enbIP is NULL!\n");
	// TODO: just temporal fix for hash look up!
	enbIP = &tempENBIP;
      }
    }

    if (lookup_code == -EINVAL) {
      //TODO: this line should not be commented. it is just commented to test the drops count
      critical_pprint("Invalid Parameteres for hash lookup!\n");
    }
    if (lookup_code == -ENOENT) {
      //TODO: this line should not be commented
      critical_pprint("Entry does not exist in the hash\n");
    }
    if (enbIP == NULL) {
      critical_pprint ("Couldn't get the proper enbIP from hash table\n");
    }
    if (*enbIP != ENB1IP && *enbIP != ENB2IP) {
      //critical_pprint ("something is wrong, enbIP is not an enbIP!\n");
      //critical_print ("enbip is %u \n", *enbIP);
    }
    prependIPHeader (pkt, EUC1IP, *enbIP, IP_TYPE_GUSER);
    prependETHF2toF3(pkt);
    meta->destination = CLEANG_TOWARD_ENB;
#if CLEANG_MULTIPORT == ACTIVATED
    meta->destination = counter % 3;
#endif

    meta->action = ONVM_NF_ACTION_OUT;
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }

  if (pkt->port == DATA_COMMAND_PORT) {
    // The following can be just one of types, but I think for now it is okay, we can use the first
    // byte to check the command type for different types of messages.
    ali_debug_pprint("A data command is received\n");
    struct CoreDataPathSet *c = (struct CoreDataPathSet*) rte_pktmbuf_mtod (pkt,char *);
    ali_debug_print ("Its message code is %u\n", c->messageCode);
    if (c->messageCode == SET_CORE_PATH_COMMAND) {
      ali_debug_pprint("it is a set path command\n");
      ali_debug_print("ue ip is: %u, enbIP is %u\n",c->ueIP, c->enbIP);
      if (c->enbIP != ENB1IP && c->enbIP != ENB2IP) {
	critical_pprint ("something is wrong! we are storing wrong enb IP in hash!\n");
	critical_print ("wrong enbip is %u\n", c->enbIP);
      }
      int* enbIP = rte_malloc( "int", sizeof (int), 0);
      *enbIP = c->enbIP;
      //int code = rte_hash_add_key_data(encap_hash, &(c->ueIP), enbIP);
      int code = rte_hash_add_key_with_hash_data(encap_hash, &(c->ueIP), MY_HASH_FUNCTION(c->ueIP), enbIP);
      if (code) {
	critical_pprint ("Error in adding enbip, ueip to the hash\n"); 
	critical_print ("code is %d\n", code);
      }
      meta->action = ONVM_NF_ACTION_DROP;
#if UTILIZATION_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &lastExitTime);
      totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

      return 0;
    }
  }
  // unhandled pacekt
  critical_pprint("We should never get here! Unknow packet! \n");
  //meta->action = ONVM_NF_ACTION_TONF;
  meta->action = ONVM_NF_ACTION_DROP;
  meta->destination = destination;
#if UTILIZATION_LOGGING == ACTIVATED
  clock_gettime(CLOCK_REALTIME, &lastExitTime);
  totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

  return 0;
}


int main(int argc, char *argv[]) {
  int arg_offset;

  const char *progname = argv[0];

  if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, &nf_info)) < 0)
    return -1;
  argc -= arg_offset;
  argv += arg_offset;
  destination = nf_info->service_id + 1;

  if (parse_app_args(argc, argv, progname) < 0)
    rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
  /*
     ali_debug_pprint("before setting hash parametres\n");
     struct rte_hash_parameters encap_hash_params = {
     .name = "CoreDataPathHash",
     .entries = NO_OF_HASH_ENTRIES_IN_CORE_FORWARDER,
     .key_len = sizeof(uint32_t),
     .hash_func = DEFAULT_HASH_FUNC,
     .hash_func_init_val = 0,
     .socket_id = rte_socket_id(),
     };
     ali_debug_pprint("after setting hash parameteres, before creating hash\n");
     encap_hash = rte_hash_create(&encap_hash_params);
     if (encap_hash == NULL) {
     critical_pprint("unable to make the hash!!\n");
     }
     ali_debug_pprint("hash created successfully\n");
  //prinf ("hello\n");
   */

  encap_hash = rte_hash_find_existing("CoreDataPathHash");
  if (encap_hash == NULL) {
    rte_panic("Failed to find hash table, errno = %d\n",
	rte_errno);
  }
  //To test we add, lookup, and remove one entity to hash
//  uint32_t key = 100, value=200;
//  printf ("before adding key\n");
//  int code = rte_hash_add_key_with_hash_data(encap_hash, &key, MY_HASH_FUNCTION(key), &value);
  //int32_t   rte_hash_add_key_with_hash_data (const struct rte_hash *h, const void *key, hash_sig_t sig, void *data)
//  printf ("after adding key, code is%d\n",code );
#if UTILIZATION_LOGGING == ACTIVATED
  clock_gettime(CLOCK_REALTIME, &lastExitTime);
  int i = 0;
  for ( i = 0 ; i < MAXIMUM_RUN_TIME_IN_SECONDS; i++) {
    utilization [i] = -1;
  }
#endif

  onvm_nflib_run(nf_info, &packet_handler);
#if UTILIZATION_LOGGING == ACTIVATED
  recordUtilizationLog ("ULogf3fwd.txt", utilization);
#endif

  critical_pprint("If we reach here, program is ending\n");
  return 0;
}
