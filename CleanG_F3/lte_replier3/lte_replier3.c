/*********************************************************************
 *                     openNetVM
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

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "lteCore.h"

#define NF_TAG "simple_forward"

#if UTILIZATION_LOGGING == ACTIVATED
long long lastRecordedSecond = 0;
//static struct timespec lastStartPeriod;
static struct timespec lastExitTime;
static unsigned long totalActiveTimeInLastPeriod;
//static unsigned long totalIdleTimeInLastPeriod;
// It is is not started with zero. current_time_second % MAXIMUM_RUN_TIME_IN_SECONDS is used for storage
static double utilization [MAXIMUM_RUN_TIME_IN_SECONDS];
#endif
struct rte_mempool *pktmbuf_pool;

/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

/* number of package between each print */
static uint32_t print_delay = 1000000;


static uint32_t destination;

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
  printf("Usage: %s [EAL args] -- [NF_LIB args] -- -d <destination> -p <print_delay>\n\n", progname);
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
  int c;
  corePrint2();
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
#if SHOW_PACKET_STATS == ENABLED
static void
do_stats_display(struct rte_mbuf* pkt) {
  const char clr[] = { 27, '[', '2', 'J', '\0' };
  const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };
  static int pkt_process = 0;
  struct ipv4_hdr* ip;

  pkt_process += print_delay;

  /* Clear screen and move to top left */
  printf("%s%s", clr, topLeft);

  printf("PACKETS\n");
  printf("-----\n");
  printf("Port : %d\n", pkt->port);
  printf("Size : %d\n", pkt->pkt_len);
  printf("N°   : %d\n", pkt_process);
  printf("\n\n");

  ip = onvm_pkt_ipv4_hdr(pkt);
  if (ip != NULL) {
    onvm_pkt_print(pkt);
  } else {
    printf("No IP4 header found\n");
  }
}
#endif

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

#if PACKET_DUMP_DEBUG == ACTIVATED
  FILE *fp;
  fp = fopen("dump.txt", "a");
  fprintf (fp, "received packet \n");
  rte_pktmbuf_dump(fp, pkt, pkt->pkt_len);
  fclose(fp);
#endif

  //ali_debug_print("debugtest %i", 11);
  //printf("%i",ALIDEBUG);

#if SHOW_PACKET_STATS == ENABLED
  static uint32_t counter = 0;
  if (++counter == print_delay && SHOW_PACKET_STATS != DISABLED) {
    do_stats_display(pkt);
    counter = 0;
  }
#endif
  
  struct ipv4_hdr *iph;
  iph = (struct ipv4_hdr *) (rte_pktmbuf_mtod (pkt,char *));
  uint32_t srcip = iph->src_addr;
  //printf ("src ip is %u\n", srcip);
  uint32_t dstip =  iph->dst_addr;
  iph->src_addr = dstip;
  iph->dst_addr = srcip;
  iph->next_proto_id = 0;




  //rte_pktmbuf_adj (pkt, sizeof (struct ipv4_hdr));
  ali_debug_print ("start sending data for %lu\n", (unsigned long) srcip);
  //SENDING packets starts here
//  struct rte_mempool *pktmbuf_pool;
  struct rte_mbuf *pkts[REPLIED_PER_PACKET-1];
  int i;

//  pktmbuf_pool = rte_mempool_lookup (PKTMBUF_POOL_NAME);
//  if (pktmbuf_pool == NULL)
//  {
//    rte_exit (EXIT_FAILURE, "Cannot find mbuf pool!\n");
//  }
  //printf ("Creating %d packets to send to %d\n", NUM_PKTS, destination);
  for (i = 0; i < REPLIED_PER_PACKET - 1; i++)
  {
    ali_debug_print2 ("Start sending packet: %d\n", i);
    struct onvm_pkt_meta *pmeta;
#if DATA_REPLIER_MEM_ALLOCATION_DEBUG == ENABLED
    int stuckInLoop = 0;
#endif

#if DATA_REPLIER_MEM_ALLOCATION_DEBUG == ENABLED
    do {
#endif
      //It seems cloned packets share physical address and they are not real replicate. So we avoid using clone function.
      //pkts[i] = rte_pktmbuf_clone(pkt, pktmbuf_pool);  //rte_pktmbuf_alloc (pktmbuf_pool);
      pkts[i] = rte_pktmbuf_alloc (pktmbuf_pool);
#if DATA_REPLIER_MEM_ALLOCATION_DEBUG == ENABLED
      if (pkts[i] == NULL) {
	printf ("cannot alloc pkt i\n");
	stuckInLoop = 1;
	continue;
      }
#endif
      char* dataPart = rte_pktmbuf_prepend (pkts[i], rte_pktmbuf_data_len(pkt));
      memcpy (dataPart, rte_pktmbuf_mtod (pkt,char *), rte_pktmbuf_data_len(pkt));
      //char* dataPart = rte_pktmbuf_prepend (pkts[i], rte_pktmbuf_data_len(pkt));
      //memcpy (dataPart, rte_pktmbuf_mtod (pkt,char *), rte_pktmbuf_data_len(pkt));
#if DATA_REPLIER_MEM_ALLOCATION_DEBUG == ENABLED
      }
    while (pkts[i] == NULL);
    if (stuckInLoop == 1) {
      printf ("got out of loop!\n");
    }
#endif
    /*    
#if DATA_DELAY_LOGGING == ENABLED
char* oldDataMem = rte_pktmbuf_prepend (pkts[i], rte_pktmbuf_data_len(pkt));
memcpy (oldDataMem, rte_pktmbuf_mtod (pkt,char *), rte_pktmbuf_data_len(pkt));
#endif
    //Add IP header
    prependIPHeader (pkts[i], dstip, srcip, 0); //is it a right next proto?*/
    pmeta = onvm_get_pkt_meta (pkts[i]);
#if SIMULATION_MODE == CLEAN_G
    pmeta->destination = CORE_FORWARDER_SERVICE_ID;
#else
    ali_debug_pprint ("sending extra data packet back to pgw\n");
    pmeta->destination = LTE_PGW1_SERVICE_ID;
#endif
    pmeta->action = ONVM_NF_ACTION_TONF;
    pkts[i]->port = DATA_PACKET_PORT;
    //TODO: ali go and readh about hash rss and find out is is better to set it or not to set it.
    //pkts[i]->hash.rss = i;
    //int j,k;
    //j = scanf("%i",&k);
    //printf("go to next packet %i",j*k);
    //sleep (.2);
#if PACKET_DUMP_DEBUG == ACTIVATED
  //FILE *fp;
      //FILE *fp;
      fp = fopen("dump.txt", "a");
      fprintf (fp, "clone packet \n");
      rte_pktmbuf_dump(fp, pkts[i], pkts[i]->pkt_len);
      fclose(fp);
#endif
    onvm_nflib_return_pkt (nf_info, pkts[i]);
  }


  // unhandled pacekt
  //printf("Unhandled packet, we shouldn't get here\n");
  //meta->action = ONVM_NF_ACTION_TONF;

#if SIMULATION_MODE == CLEAN_G
  meta->destination = CORE_FORWARDER_SERVICE_ID;
#else
  ali_debug_pprint("send original data packet back to pgw\n");
  meta->destination = LTE_PGW1_SERVICE_ID;
#endif
  pkt->port = DATA_PACKET_PORT;
  meta->action = ONVM_NF_ACTION_TONF;
  //meta->destination = destination;
#if UTILIZATION_LOGGING == ACTIVATED
  clock_gettime(CLOCK_REALTIME, &lastExitTime);
  totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

#if PACKET_DUMP_DEBUG == ACTIVATED
  fp = fopen("dump.txt", "a");
  fprintf (fp, "updated packet \n");
  rte_pktmbuf_dump(fp, pkt, pkt->pkt_len);
  fclose(fp);
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

  pktmbuf_pool = rte_mempool_lookup (PKTMBUF_POOL_NAME);
  if (pktmbuf_pool == NULL)
  {
    rte_exit (EXIT_FAILURE, "Cannot find mbuf pool!\n");
  }
#if UTILIZATION_LOGGING == ACTIVATED
  clock_gettime(CLOCK_REALTIME, &lastExitTime);
  int i = 0;
  for ( i = 0 ; i < MAXIMUM_RUN_TIME_IN_SECONDS; i++) {
    utilization [i] = -1;
  }
#endif

  onvm_nflib_run(nf_info, &packet_handler);
#if UTILIZATION_LOGGING == ACTIVATED
  recordUtilizationLog ("ULogf3rpl.txt", utilization);
#endif

  printf("If we reach here, program is ending");
  return 0;
}
