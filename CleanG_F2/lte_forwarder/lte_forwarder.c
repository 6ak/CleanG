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
#include <rte_ether.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "lteCore.h"

#define NF_TAG "simple_forward"

/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

#if UTILIZATION_LOGGING == ACTIVATED
long long lastRecordedSecond = 0;
//static struct timespec lastStartPeriod;
static struct timespec lastExitTime;
static unsigned long totalActiveTimeInLastPeriod;
//static unsigned long totalIdleTimeInLastPeriod;
// It is is not started with zero. current_time_second % MAXIMUM_RUN_TIME_IN_SECONDS is used for storage
static double utilization [MAXIMUM_RUN_TIME_IN_SECONDS];
#endif


/* number of package between each print */
static uint32_t print_delay = 1000000;


static uint32_t destination;

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
  printf("Usagae: %s [EAL args] -- [NF_LIB args] -- -d <destination> -p <print_delay>\n\n", progname);
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

static int
packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta, __attribute__((unused)) struct onvm_nf_info *nf_info ) {

/*
  FILE *fp;
  fp = fopen("dump.txt", "a");
  fprintf (fp, "received packet \n");
  rte_pktmbuf_dump(fp, pkt, pkt->pkt_len);
  fclose(fp);
*/
static int data_counter = 0;
static int control_counter = 0;
static int total_counter = 0;
//if (pkt->pkt_len < 100)
//  small_counter++;
//else
//  large_counter++;
//printf ("%u\n",pkt->pkt_len);
//if ((small_counter + large_counter) % 10000 == 9999)
//  printf ("%d small %d large \n", small_counter, large_counter);
#if UTILIZATION_LOGGING == ACTIVATED
  struct timespec currentTime;
  clock_gettime(CLOCK_REALTIME, &currentTime);
  if (currentTime.tv_sec - lastRecordedSecond >= 1) {
    lastRecordedSecond = currentTime.tv_sec;
    // There is a trade of in using total idel time. by using total idle time we could double check for correctness,
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
  static uint32_t counter = 0;
  if (++counter == print_delay && SHOW_PACKET_STATS != DISABLED) {
    do_stats_display(pkt);
    counter = 0;
  }

  //	struct ether_hdr * eh;
  //        eh = rte_pktmbuf_mtod (pkt,struct ether_hdr*);
  ali_debug_pprint ("a packet is received\n");
  //TODO: I removed the checks for packet being from outside, make sure it is Okay!
  //        if ((eh->s_addr.addr_bytes[0] == 140u) & (eh->s_addr.addr_bytes[1] == 220u)
  //           && (eh->s_addr.addr_bytes[2] == 212u) && (eh->s_addr.addr_bytes[3] == 172u)
  //           && (eh->s_addr.addr_bytes[4] == 194u) && (eh->s_addr.addr_bytes[5] == 16u) )
  //        {
  //a packet received from outside
  ali_debug_pprint("a packet received from outside\n");
  // remove ethernet header
  rte_pktmbuf_adj(pkt, 14);

  struct ipv4_hdr *iph;
  iph = rte_pktmbuf_mtod (pkt,struct ipv4_hdr*);
//TODO: Ali the following code is for counting control and data packets.
//struct ipv4_hdr *iph;
//iph = (struct ipv4_hdr *) rte_ctrlmbuf_data (pkt);
if (iph->next_proto_id == IP_TYPE_GUSER)
{
  data_counter++;
  total_counter++;
  //printf ("data\n");
} else {
  control_counter++;
  total_counter++;
  //printf ("control\n");
}
if (total_counter >= 10000) {
  ali_debug_print ("data %u, control %u \n", data_counter, control_counter);
  total_counter = 0;
}

  //check if packet is destined to enb-1
  if (iph->dst_addr  == rte_be_to_cpu_32(ENB1IP))
  {
    ali_debug_pprint("packet is for enodB 1\n");
    meta->destination = LTE_ENB1_SERVICE_ID;
    meta->action = ONVM_NF_ACTION_TONF;
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }


  if (iph->dst_addr  == rte_be_to_cpu_32(ENB2IP))
  {
    ali_debug_pprint("packet is for enodB 2\n");
    meta->destination = LTE_ENB2_SERVICE_ID;
    meta->action = ONVM_NF_ACTION_TONF;
    //printf ("packets for enb2\n");
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }
  // TODO: The following line only works for clean g, how about lte? the same IP for mme and core probably make it okay
  /*if (iph->dst_addr == rte_be_to_cpu_32(EUC1IP) {
    ali_debug_pprint("packet is for mme/core\n");
    meta->destination = 0;
    meta->action = ONVM_NF_ACTION_TOPORT;
    }*/
  //	}
  // unhandled pacekt
  printf("We should never get here! unhandled packet!\n");
  printf("iph dest is u %u d %d toU %u toD %d \n", iph->dst_addr, iph->dst_addr, rte_be_to_cpu_32(iph->dst_addr), rte_be_to_cpu_32(iph->dst_addr));
  printMbuf (pkt);
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
#if UTILIZATION_LOGGING == ACTIVATED
  clock_gettime(CLOCK_REALTIME, &lastExitTime);
  int i = 0;
  for ( i = 0 ; i < MAXIMUM_RUN_TIME_IN_SECONDS; i++) {
    utilization [i] = -1;
  }
#endif

  onvm_nflib_run(nf_info, &packet_handler);
#if UTILIZATION_LOGGING == ACTIVATED
  recordUtilizationLog ("ULogf2fwd.txt", utilization);
#endif

  printf("If we reach here, program is ending");
  return 0;
}
