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
#include <rte_malloc.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "lteCore.h"
#include "openFlowHelper.h"

#define NF_TAG "simple_forward"

/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

/* number of package between each print */
static uint32_t print_delay = 1000000;
static uint32_t assignedIPCounter = 0;
static uint32_t s5ulCounter = 0;
static uint32_t iptos5dl[USER_STATE_SIZE];
//users[lam->imsi].ip = MME1_FIRST_IP + assignedIPCounter;
//          assignedIPCounter++;
//static struct lteMMEUserState users[USER_STATE_SIZE];


#if UTILIZATION_LOGGING == ACTIVATED
long long lastRecordedSecond = 0;
//static struct timespec lastStartPeriod;
static struct timespec lastExitTime;
static unsigned long totalActiveTimeInLastPeriod;
//static unsigned long totalIdleTimeInLastPeriod;
// It is is not started with zero. current_time_second % MAXIMUM_RUN_TIME_IN_SECONDS is used for storage
static double utilization [MAXIMUM_RUN_TIME_IN_SECONDS];
#endif


#if TIME_LOGGING == ACTIVATED
//static struct timeLoggingState tl[NUMBER_OF_USERS];
static struct timespec tl[NUMBER_OF_USERS][MAX_NUMBER_OF_MESSAGE_CODES];
#define TL_T13  0
#define TL_T13S 1
#define TL_I12  2
#define TL_H14  3
#define TL_D3   4
#define TL_D3S  5
#endif


static uint32_t destination;

/*
 * Print a usage message
 */

void sendLTE13Response (struct PgwOpLte13* op13);
void sendDLTE3Response (struct GwOpPlaceHolder* ph);


void sendLTE13Response (struct PgwOpLte13* op13) {
  ali_debug_pprint ("sending response to lte 13\n");
#if TIME_LOGGING == ACTIVATED
  clock_gettime(CLOCK_REALTIME, &tl[op13->imsi][TL_T13S]);
#endif

  struct lte18EpsRes *ler18;


  struct rte_mempool *pktmbuf_pool;
  struct rte_mbuf* pkt;
  pktmbuf_pool = rte_mempool_lookup (PKTMBUF_POOL_NAME);
  if (pktmbuf_pool == NULL)
  {
    ali_debug_pprint("cannot find pooooool!!!!exit!\n");
    rte_exit (EXIT_FAILURE, "Cannot find mbuf pool!\n");
  }
  pkt = rte_pktmbuf_alloc (pktmbuf_pool);
  ler18 = (struct lte18EpsRes *) rte_pktmbuf_prepend (pkt, sizeof (struct lte18EpsRes));
  ler18->messageCode = LTE_18_EPS_RES_CODE;
  ler18->imsi = op13->imsi;
  ler18->ip = op13->ip;
  ler18->s5ul = s5ulCounter;
  s5ulCounter++;
  prependIPHeader (pkt, PGW1IP, SGW1IP, IP_TYPE_GCONTROL);
  //prependETHF3toF2(pkt);
  struct onvm_pkt_meta *meta;

  meta =    onvm_get_pkt_meta (pkt);
  meta->destination = LTE_SGW1_SERVICE_ID;
  meta->action = ONVM_NF_ACTION_TONF;
  ali_debug_pprint ("Req for eps session command lte18 is being sent\n");
  onvm_nflib_return_pkt (pkt);
  //meta->action = ONVM_NF_ACTION_DROP;
  return;
}

void sendDLTE3Response (struct GwOpPlaceHolder* ph) {
  ali_debug_pprint ("sending response to Dlte 3\n");
  struct dLTE6 *d6;
#if TIME_LOGGING == ACTIVATED
  clock_gettime(CLOCK_REALTIME, &tl[ph->imsi][TL_D3S]);
#endif


  struct rte_mempool *pktmbuf_pool;
  struct rte_mbuf* pkt;
  pktmbuf_pool = rte_mempool_lookup (PKTMBUF_POOL_NAME);
  if (pktmbuf_pool == NULL)
  {
    ali_debug_pprint("cannot find pooooool!!!!exit!\n");
    rte_exit (EXIT_FAILURE, "Cannot find mbuf pool!\n");
  }
  pkt = rte_pktmbuf_alloc (pktmbuf_pool);
  d6 = (struct dLTE6 *) rte_pktmbuf_prepend (pkt, sizeof (struct dLTE6));
  d6->messageCode = DLTE6_MESSAGE_CODE;
  d6->imsi = ph->imsi;
  prependIPHeader (pkt, PGW1IP, SGW1IP, IP_TYPE_GCONTROL);
  //prependETHF3toF2(pkt);
  struct onvm_pkt_meta *meta;

  meta =    onvm_get_pkt_meta (pkt);
  meta->destination = LTE_SGW1_SERVICE_ID;
  meta->action = ONVM_NF_ACTION_TONF;
  ali_debug_pprint ("dlte 6 is being sent\n");
  onvm_nflib_return_pkt (pkt);
  return;
}

  static void
usage (const char *progname)
{
  printf ("Usage: %s [EAL args] -- [NF_LIB args] -- -d <destination> -p <print_delay>\n\n", progname);
}

/*
 * Parse the application arguments.
 */
  static int
parse_app_args (int argc, char *argv[], const char *progname)
{
  int c;
  corePrint2 ();
  while ((c = getopt (argc, argv, "d:p:")) != -1)
  {
    switch (c)
    {
      case 'd':
	destination = strtoul (optarg, NULL, 10);
	break;
      case 'p':
	print_delay = strtoul (optarg, NULL, 10);
	break;
      case '?':
	usage (progname);
	if (optopt == 'd')
	  RTE_LOG (INFO, APP, "Option -%c requires an argument.\n", optopt);
	else if (optopt == 'p')
	  RTE_LOG (INFO, APP, "Option -%c requires an argument.\n", optopt);
	else if (isprint (optopt))
	  RTE_LOG (INFO, APP, "Unknown option `-%c'.\n", optopt);
	else
	  RTE_LOG (INFO, APP, "Unknown option character `\\x%x'.\n", optopt);
	return -1;
      default:
	usage (progname);
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
do_stats_display (struct rte_mbuf *pkt)
{
  const char clr[] = { 27, '[', '2', 'J', '\0' };
  const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };
  static int pkt_process = 0;
  struct ipv4_hdr *ip;

  pkt_process += print_delay;

  /* Clear screen and move to top left */
  printf ("%s%s", clr, topLeft);

  printf ("PACKETS\n");
  printf ("-----\n");
  printf ("Port : %d\n", pkt->port);
  printf ("Size : %d\n", pkt->pkt_len);
  printf ("N°   : %d\n", pkt_process);
  printf ("\n\n");

  ip = onvm_pkt_ipv4_hdr (pkt);
  if (ip != NULL)
  {
    onvm_pkt_print (pkt);
  }
  else
  {
    printf ("No IP4 header found\n");
  }
}

  static int
packet_handler (struct rte_mbuf *pkt, struct onvm_pkt_meta *meta)
{

#if UTILIZATION_LOGGING == ACTIVATED
  struct timespec currentTime;
  clock_gettime(CLOCK_REALTIME, &currentTime);
  if (currentTime.tv_sec - lastRecordedSecond >= 1) {
    lastRecordedSecond = currentTime.tv_sec;
    // There is a trade of in using total idel time. by using total idle time we could double check for correctness, but it adde
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
  //ali_debug_print("%i",ALIDEBUG);

  if (pkt->port == SDN_F4_TOWARD_OF_SERVER) {
    int output = handleOfPackets(pkt, meta);
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return output;
  }

  static uint32_t counter = 0;
  if (++counter == print_delay && PACKET_COUNTER_STATS == ACTIVATED)
  {
    do_stats_display (pkt);
    counter = 0;
  }
  struct ipv4_hdr *iph;
  iph = (struct ipv4_hdr *) rte_ctrlmbuf_data (pkt);


  //uint32_t tempSrcIP = rte_be_to_cpu_32 (iph->src_addr);
  //packet is control packet
  if (iph->next_proto_id == IP_TYPE_GUSER)
  {
    ali_debug_pprint ("a upward data packet received\n");
    // remove the ip header
    rte_pktmbuf_adj (pkt, 20);
    //remove ge header
    rte_pktmbuf_adj (pkt, sizeof (struct GTPUHeader));
    // ali_debug_pprint ("before ip\n");
    //  prependIPHeader (pkt, PGW1IP, PGW1IP, IP_TYPE_GUSER);
    ali_debug_pprint ("data message is being forwarded!\n");
    //struct onvm_pkt_meta *pmeta;
    //pmeta = onvm_get_pkt_meta (pkt);
    meta->destination = LTE_REP1_SERVICE_ID;
    meta->action = ONVM_NF_ACTION_TONF;
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }
  if (pkt->port == DATA_PACKET_PORT)
  {
    ali_debug_pprint ("a packet received from replier\n");
    struct ipv4_hdr *iph;
    iph = (struct ipv4_hdr *) (rte_ctrlmbuf_data (pkt));
    uint32_t tempip = rte_be_to_cpu_32 (iph->dst_addr);
    ali_debug_print2 ("resulted ip %lu\n", (unsigned long) tempip - PGW1_FIRST_IP);
    uint32_t temps5dl = iptos5dl[tempip - PGW1_FIRST_IP];
    ali_debug_pprint ("before gre\n");
    ali_debug_print2 ("temp s1ul %lu", (unsigned long) temps5dl);
    addGTPUHeader (pkt, temps5dl);
    ali_debug_pprint ("before ip\n");
    prependIPHeader (pkt, PGW1IP, SGW1IP, IP_TYPE_GUSER);
    //ali_debug_pprint("before ethernet\n");
    //prependETHF2toF3 (pkt);
    ali_debug_pprint ("data message is being forwarded!\n");
    //send directly to port
    //ali_debug_print ("check 3\n");
    struct onvm_pkt_meta *pmeta;
    pmeta = onvm_get_pkt_meta (pkt);
    pmeta->destination = LTE_SGW1_SERVICE_ID;
    pmeta->action = ONVM_NF_ACTION_TONF;
    //ali_debug_print ("check 4\n");
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;

  }


  //packet is control packet
  if (iph->next_proto_id == IP_TYPE_GCONTROL)
  {
    ali_debug_pprint ("control packet received\n");
    // remove the ip header
    rte_pktmbuf_adj (pkt, 20);
    if (*rte_ctrlmbuf_data (pkt) == LTE_13_EPS_REQ_CODE)
    {
      ali_debug_pprint ("a eps req lte 13 message received \n");
      struct lte13EpsReq *ler13 = (struct lte13EpsReq *) rte_ctrlmbuf_data (pkt);
      uint32_t tempImsi = ler13->imsi;
#if TIME_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_T13]);
#endif

      if (tempImsi > USER_STATE_SIZE)
	critical_print ("large imsi %u \n", tempImsi);
      uint32_t temps5dl = ler13->s5dl;
      struct PgwOpLte13* op13;
      //printf ("before malloc\n");
      op13 = rte_malloc("PgwOpLte13", sizeof(struct PgwOpLte13), 0);
      if (op13 == NULL) {
      	printf ("cannot allocate op13\n");
      }
      op13->messageCode = PGW_OP_LTE13_CODE;
      op13->imsi = tempImsi;
      op13->ip = PGW1_FIRST_IP + assignedIPCounter;
      ali_debug_print("aliiiiii! op13 ip is %u\n", op13->ip);
      op13->s5dl = temps5dl;
      /* struct lte18EpsRes *ler18;
	 if (sizeof (struct lte18EpsRes) - sizeof (struct lte13EpsReq) > 0)
	 {			// more space is needed in the packet
	 rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct lte18EpsRes) - sizeof (struct lte13EpsReq)));
	 ali_debug_pprint ("increasing the size\n");
	 }
	 else
	 {			// the packet is already larger than it shold be
	 rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct lte13EpsReq) - sizeof (struct lte18EpsRes)));
	 ali_debug_pprint ("decreasing the size\n");
	 }
	 ler18 = (struct lte18EpsRes *) rte_ctrlmbuf_data (pkt);
	 ler18->messageCode = LTE_18_EPS_RES_CODE;
	 ler18->imsi = tempImsi;
	 ali_debug_print2 ("assingedIPcounter %lu \n", (unsigned long) assignedIPCounter);
	 ler18->ip = PGW1_FIRST_IP + assignedIPCounter;
	 ler18->s5ul = s5ulCounter;
	 s5ulCounter++;*/
      //TODO: I changed the order of folliwng two lines. new order makes more sense to me.
      // but original order was reverse, maybe there was a reason to do so.
      iptos5dl[assignedIPCounter] = temps5dl;
      assignedIPCounter++;

      //snali_debug_print ( ar->autn, 256, "%s", "This is autn!" );
      //printf ("before send in\n");
      sendPacketIn(op13, sizeof (struct PgwOpLte13));
      //printf ("before free\n");
      rte_free (op13);
      //TODO: ali use the following lines to 
      /*  prependIPHeader (pkt, PGW1IP, SGW1IP, IP_TYPE_GCONTROL);
      //prependETHF3toF2(pkt);
      meta->destination = LTE_SGW1_SERVICE_ID;
      meta->action = ONVM_NF_ACTION_TONF;
      ali_debug_pprint ("Req for eps session command is being sent\n");*/
      meta->action = ONVM_NF_ACTION_DROP;
#if UTILIZATION_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &lastExitTime);
      totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

      return 0;
    }

    if (*rte_ctrlmbuf_data (pkt) == HLTE14_MESSAGE_CODE)
    {
      ali_debug_pprint ("hlte 14  message received \n");
      struct hLTE14 *l14 = (struct hLTE14 *) rte_ctrlmbuf_data (pkt);
      uint32_t tempImsi = l14->imsi;
#if TIME_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_H14]);
#endif

      //uint32_t temps5dl = l14->s5dl;
      struct hLTE17 *l17;
      if (sizeof (struct hLTE17) - sizeof (struct hLTE14) > 0)
      {                   // more space is needed in the packet
	rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct hLTE17) - sizeof (struct hLTE14)));
	ali_debug_pprint2 ("increasing the size\n");
      }
      else
      {                   // the packet is already larger than it shold be
	rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct hLTE14) - sizeof (struct hLTE17)));
	ali_debug_pprint2 ("decreasing the size\n");
      }
      l17 = (struct hLTE17 *) rte_ctrlmbuf_data (pkt);
      l17->messageCode = HLTE17_MESSAGE_CODE;
      l17->imsi = tempImsi;
      //ali_debug_print2 ("assingedIPcounter %lu \n", (unsigned long) assignedIPCounter);
      //ler18->ip = PGW1_FIRST_IP + assignedIPCounter;
      //ler18->s5ul = s5ulCounter;
      //s5ulCounter++;
      //assignedIPCounter++;
      //iptos5dl[assignedIPCounter] = temps5dl;
      //snali_debug_print ( ar->autn, 256, "%s", "This is autn!" );

      prependIPHeader (pkt, PGW1IP, SGW1IP, IP_TYPE_GCONTROL);
      //prependETHF3toF2(pkt);
      meta->destination = LTE_SGW1_SERVICE_ID;
      meta->action = ONVM_NF_ACTION_TONF;
      ali_debug_pprint ("hlte 17 is being sent\n");
#if UTILIZATION_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &lastExitTime);
      totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

      return 0;
    }
    // d3
    if (*rte_ctrlmbuf_data (pkt) == DLTE3_MESSAGE_CODE)
    {
      ali_debug_pprint ("dlte 3  message received \n");
      struct dLTE3 *d3 = (struct dLTE3 *) rte_ctrlmbuf_data (pkt);
      uint32_t tempImsi = d3->imsi;
#if TIME_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_D3]);
#endif

      //printf ("before malloc 2\n");
      struct GwOpPlaceHolder* ph = rte_malloc("GwOpPlaceHolder", sizeof (struct GwOpPlaceHolder), 0);
      if (ph == NULL) {
	printf ("cannot allocate ph\n");
      }
      ph->messageCode = PGW_OP_DETACH_CODE;
      ph->imsi = tempImsi;
      //printf ("before packet in 2\n");
      sendPacketIn(ph, sizeof( struct GwOpPlaceHolder));
      //printf ("before free 2\n");
      rte_free(ph);
      //uint32_t temps5dl = l14->s5dl;
      /* struct dLTE6 *d6;
	 if (sizeof (struct dLTE6) - sizeof (struct dLTE3) > 0)
	 {                   // more space is needed in the packet
	 rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct dLTE6) - sizeof (struct dLTE3)));
	 ali_debug_pprint2 ("increasing the size\n");
	 }
	 else
	 {                   // the packet is already larger than it shold be
	 rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct dLTE3) - sizeof (struct dLTE6)));
	 ali_debug_pprint2 ("decreasing the size\n");
	 }
	 d6 = (struct dLTE6 *) rte_ctrlmbuf_data (pkt);
	 d6->messageCode = DLTE6_MESSAGE_CODE;
	 d6->imsi = tempImsi;
      //ali_debug_print2 ("assingedIPcounter %lu \n", (unsigned long) assignedIPCounter);
      //ler18->ip = PGW1_FIRST_IP + assignedIPCounter;
      //ler18->s5ul = s5ulCounter;
      //s5ulCounter++;
      //assignedIPCounter++;
      //iptos5dl[assignedIPCounter] = temps5dl;
      //snali_debug_print ( ar->autn, 256, "%s", "This is autn!" );

      prependIPHeader (pkt, PGW1IP, SGW1IP, IP_TYPE_GCONTROL);
      //prependETHF3toF2(pkt);
      meta->destination = LTE_SGW1_SERVICE_ID;
      meta->action = ONVM_NF_ACTION_TONF;
      ali_debug_pprint ("dlte 6 is being sent\n");*/
      meta->action = ONVM_NF_ACTION_DROP;
#if UTILIZATION_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &lastExitTime);
      totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

      return 0;
    }
    // i12
    if (*rte_ctrlmbuf_data (pkt) == ILTE12_MESSAGE_CODE)
    {
      ali_debug_pprint ("ilte 12  message received \n");
      struct iLTE12 *i12 = (struct iLTE12 *) rte_ctrlmbuf_data (pkt);
      uint32_t tempImsi = i12->imsi;
#if TIME_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_I12]);
#endif

      //uint32_t temps5dl = l14->s5dl;
      struct iLTE15 *i15;
      if (sizeof (struct iLTE15) - sizeof (struct iLTE12) > 0)
      {                   // more space is needed in the packet
	rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct iLTE12) - sizeof (struct iLTE15)));
	ali_debug_pprint2 ("increasing the size\n");
      }
      else
      {                   // the packet is already larger than it shold be
	rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct iLTE15) - sizeof (struct iLTE12)));
	ali_debug_pprint2 ("decreasing the size\n");
      }
      i15 = (struct iLTE15 *) rte_ctrlmbuf_data (pkt);
      i15->messageCode = ILTE15_MESSAGE_CODE;
      i15->imsi = tempImsi;
      //ali_debug_print2 ("assingedIPcounter %lu \n", (unsigned long) assignedIPCounter);
      //ler18->ip = PGW1_FIRST_IP + assignedIPCounter;
      //ler18->s5ul = s5ulCounter;
      //s5ulCounter++;
      //assignedIPCounter++;
      //iptos5dl[assignedIPCounter] = temps5dl;
      //snali_debug_print ( ar->autn, 256, "%s", "This is autn!" );

      prependIPHeader (pkt, PGW1IP, SGW1IP, IP_TYPE_GCONTROL);
      //prependETHF3toF2(pkt);
      meta->destination = LTE_SGW1_SERVICE_ID;
      meta->action = ONVM_NF_ACTION_TONF;
      ali_debug_pprint ("ilte 15 is being sent\n");
#if UTILIZATION_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &lastExitTime);
      totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

      return 0;
    }

  }


  // unhandled pacekt
  printf ("Unhandled packet Code\n");
  //meta->action = ONVM_NF_ACTION_TONF;
  meta->action = ONVM_NF_ACTION_DROP;
  meta->destination = destination;
#if UTILIZATION_LOGGING == ACTIVATED
  clock_gettime(CLOCK_REALTIME, &lastExitTime);
  totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

  return 0;
}


  int
main (int argc, char *argv[])
{
  int arg_offset;

  const char *progname = argv[0];

  if ((arg_offset = onvm_nflib_init (argc, argv, NF_TAG)) < 0)
    return -1;
  argc -= arg_offset;
  argv += arg_offset;
  destination = nf_info->service_id + 1;

  if (parse_app_args (argc, argv, progname) < 0)
    rte_exit (EXIT_FAILURE, "Invalid command-line arguments\n");

  if (SIMULATION_MODE == SDN) {
    makeOfConnection();
  }
#if UTILIZATION_LOGGING == ACTIVATED
  clock_gettime(CLOCK_REALTIME, &lastExitTime);
  int i = 0;
  for ( i = 0 ; i < MAXIMUM_RUN_TIME_IN_SECONDS; i++) {
    utilization [i] = -1;
  }
#endif

  onvm_nflib_run (nf_info, &packet_handler);
#if UTILIZATION_LOGGING == ACTIVATED
  recordUtilizationLog ("ULogf4pgw.txt", utilization);
#endif
#if TIME_LOGGING == ACTIVATED
  writeTimeLogToFile ("f4pgw.txt", tl);
#endif
  printf ("If we reach here, program is ending\n");
  return 0;
}
