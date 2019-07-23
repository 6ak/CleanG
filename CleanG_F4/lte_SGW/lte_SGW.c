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
#include <rte_hash.h>
#include <rte_malloc.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "lteCore.h"

#define NF_TAG "simple_forward"
/*
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Werror"
#undef CRITICALPRINT
#undef ALIDEBUG
#undef ALIDEBUG2
#define CRITICALPRINT 1
#define ALIDEBUG 1
#define ALIDEBUG2 1
#pragma GCC diagnostic pop
*/

#include "openFlowHelper.h"
/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

/* number of package between each print */
static uint32_t print_delay = 1000000;
static uint32_t s5dlCounter = 0;
static uint32_t s1ulCounter = 0;
//static uint32_t s1ultos5ul[USER_STATE_SIZE+MAX_NUM_HANDOVER];
//static uint32_t s1ultos1dl[USER_STATE_SIZE+MAX_NUM_HANDOVER];
//static uint32_t s5dltos1dl[USER_STATE_SIZE+MAX_NUM_HANDOVER];
struct rte_hash *s1ultos5ul_hash;
struct rte_hash *s1ultos1dl_hash;
struct rte_hash *s5dltos1dl_hash;
int setState (struct rte_hash* state_hash, uint32_t key, uint32_t value);
static uint32_t retrievestate (struct rte_hash* state_hash, uint32_t hashKey, uint32_t* error_stat) {
  *error_stat = 0;
  uint32_t * hashValue = NULL;
  int lookup_code = rte_hash_lookup_data (state_hash, &hashKey,(void**) &hashValue);
  //ali_debug_print("look up code is %d\n",lookup_code);
  // TODO: It seems the Api's document is not ritht! and this function returns the place in the hash!
  if (lookup_code < 0) {
    *error_stat = 1;
    //critical_pprint("problem in hash table look up!\n");
    //critical_print("look up code is: %d \n", lookup_code);
    if (hashValue != NULL) {
      //critical_print ("hashValue is %u\n", *hashValue);
    } else {
      //critical_pprint ("enbIP is NULL!\n");
      // TODO: just temporal fix for hash look up!
      //enbIP = &tempENBIP;
    }
  }

  if (lookup_code == -EINVAL) {
    //TODO: this line should not be commented. it is just commented to test the drops count
    critical_pprint("Invalid Parameteres for hash lookup!\n");
  }
  if (lookup_code == -ENOENT) {
    //TODO: this line should not be commented
    //critical_pprint("Entry does not exist in the hash\n");
  }
  if (hashValue == NULL || lookup_code < 0) {
    //critical_pprint ("Couldn't get the proper enbIP from hash table\n");
    // TODO: This return zero is a temporary fix! it is not right to do it.
    *error_stat = 1;
    return 0;
  } else {
    return *hashValue;
  }
}

int setState (struct rte_hash* state_hash, uint32_t key, uint32_t value) {
  int* valuePointer = rte_malloc( "uint32_t", sizeof (uint32_t), 0);
  if (valuePointer != NULL) {
    *valuePointer = value;
    int code = rte_hash_add_key_data(state_hash, &key, valuePointer);
    if (code) {
      critical_pprint ("Error in adding enbip, ueip to the hash\n");
      critical_print ("code is %d\n", code);
      return code;
    } else {
      return 0;
    }
  } else {
    printf("cannot allocate memory for the hash!\n");
    return 0;
  }
}




struct rte_hash* users_hash;
//static struct lteSGWUserState users[USER_STATE_SIZE];
static struct lteSGWUserState* retrieveUserState (uint32_t hashKey) {
  struct lteSGWUserState * hashValue = NULL;
  int lookup_code = rte_hash_lookup_data (users_hash, &hashKey,(void**) &hashValue);
  ali_debug_print("look up code is %d\n",lookup_code);
  // TODO: It seems the Api's document is not ritht! and this function returns the place in the hash!
  if (lookup_code < 0) {
    //critical_pprint("problem in hash table look up!\n");
    //critical_print("look up code is: %d \n", lookup_code);
    if (hashValue != NULL) {
      critical_pprint ("hashValue is not null but code is negative\n");
    } else {
      //critical_pprint ("enbIP is NULL!\n");
      // TODO: just temporal fix for hash look up!
      //enbIP = &tempENBIP;
    }
  }

  if (lookup_code == -EINVAL) {
    //TODO: this line should not be commented. it is just commented to test the drops count
    critical_pprint("Invalid Parameteres for hash lookup!\n");
    return NULL;
  }
  if (lookup_code == -ENOENT) {
    //TODO: this line should not be commented
    //critical_print("Entry does not exist in the hash %u\n", hashKey);
    return NULL;
  }
  if (hashValue == NULL || lookup_code < 0) {
    //critical_pprint ("Couldn't get the proper enbIP from hash table\n");
    // TODO: This return zero is a temporary fix! it is not right to do it.
    return NULL;
  } else {
    return hashValue;
  }
}

static struct lteSGWUserState* addNewKey (uint32_t key) {
  //printf ("%d\n", key);
  struct lteSGWUserState* valuePointer = rte_malloc( "uint32_t", sizeof (struct lteSGWUserState), 0);
  if (valuePointer != NULL) {
    int code = rte_hash_add_key_data(users_hash, &key, valuePointer);
    if (code) {
      critical_pprint ("Error in adding enbip, ueip to the hash\n");
      critical_print ("code is %d\n", code);
      return NULL;
    } else {
      return valuePointer;
    }
  } else {
    printf("cannot allocate memory for the hash!\n");
    return NULL;
  }
}

static uint32_t destination;
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
// TODO: the following line is actually for hlte6, make necessary changes.
// for now, we keep it as is, also there may be some changes in the excel processing sheets.!
#define TL_T4S  0
#define TL_T12  1
#define TL_T17S 2
#define TL_T18  3
#define TL_T27  4
#define TL_T27S 5
#define TL_A2   6
#define TL_A2S  7
#define TL_I11  8
#define TL_I15S 9
#define TL_H5   10
#define TL_H13  11
#define TL_H15  12
#define TL_H17  13
#define TL_H17S 14
#define TL_H21  15
#define TL_H21S 16
#define TL_D2   17
#define TL_D6   18
#define TL_D6S  19
#endif


void sendLTE18Response (struct SgwOpLte18* so18);
void sendLTE5Response (struct SgwOpLte5* so5);
void sendLTE28Response (struct SgwOpLte28* so28);
void sendLTED7Response (struct GwOpPlaceHolder* ph);
void sendLTEI16Response (struct GwOpPlaceHolder* ph);
void sendLTEA3Response (struct GwOpPlaceHolder* ph);
void sendLTEH22Response (struct GwOpPlaceHolder* ph);
void sendLTEH18Response (struct GwOpPlaceHolder* ph);




void sendLTED7Response (struct GwOpPlaceHolder* ph) {
#if TIME_LOGGING == ACTIVATED
  clock_gettime(CLOCK_REALTIME, &tl[ph->imsi][TL_D6S]);
#endif

  ali_debug_pprint ("sending response to dlte 6\n");
  struct dLTE7 *d7;
  struct rte_mempool *pktmbuf_pool;
  struct rte_mbuf* pkt;
  pktmbuf_pool = rte_mempool_lookup (PKTMBUF_POOL_NAME);
  if (pktmbuf_pool == NULL)
  {
    ali_debug_pprint("cannot find pooooool!!!!exit!\n");
    rte_exit (EXIT_FAILURE, "Cannot find mbuf pool!\n");
  }
  pkt = rte_pktmbuf_alloc (pktmbuf_pool);
  d7 = (struct dLTE7 *) rte_pktmbuf_prepend (pkt, sizeof (struct dLTE7));
  d7->messageCode = DLTE7_MESSAGE_CODE;
  d7->imsi = ph->imsi;
  prependIPHeader (pkt, SGW1IP, MME1IP, IP_TYPE_GCONTROL);
  struct onvm_pkt_meta *meta;
  meta =    onvm_get_pkt_meta (pkt);
  //meta->destination = LTE_SGW1_SERVICE_ID;
  meta->destination = LTE_MME1_SERVICE_ID;
  meta->action = ONVM_NF_ACTION_TONF;
  onvm_nflib_return_pkt (pkt);
  ali_debug_pprint ("Req for eps session command dlte7 is being sent\n");
  return;
}

void sendLTEI16Response (struct GwOpPlaceHolder* ph) {
#if TIME_LOGGING == ACTIVATED
  clock_gettime(CLOCK_REALTIME, &tl[ph->imsi][TL_I15S]);
#endif

  ali_debug_pprint ("sending response to ilte 16\n");
  struct iLTE16 *i16;
  struct rte_mempool *pktmbuf_pool;
  struct rte_mbuf* pkt;
  pktmbuf_pool = rte_mempool_lookup (PKTMBUF_POOL_NAME);
  if (pktmbuf_pool == NULL)
  {
    ali_debug_pprint("cannot find pooooool!!!!exit!\n");
    rte_exit (EXIT_FAILURE, "Cannot find mbuf pool!\n");
  }
  pkt = rte_pktmbuf_alloc (pktmbuf_pool);
  i16 = (struct iLTE16 *) rte_pktmbuf_prepend (pkt, sizeof (struct iLTE16));
  i16->messageCode = ILTE16_MESSAGE_CODE;
  i16->imsi = ph->imsi;
  prependIPHeader (pkt, SGW1IP, MME1IP, IP_TYPE_GCONTROL);
  struct onvm_pkt_meta *meta;
  meta =    onvm_get_pkt_meta (pkt);
  meta->destination = LTE_MME1_SERVICE_ID;
  meta->action = ONVM_NF_ACTION_TONF;
  onvm_nflib_return_pkt (pkt);
  ali_debug_pprint ("Req for eps session command ilte16 is being sent\n");
  return;
}

void sendLTEA3Response (struct GwOpPlaceHolder* ph) {
#if TIME_LOGGING == ACTIVATED
  clock_gettime(CLOCK_REALTIME, &tl[ph->imsi][TL_A2S]);
#endif

  ali_debug_pprint ("sending response to alte 2\n");
  struct aLTE3 *a3;
  struct rte_mempool *pktmbuf_pool;
  struct rte_mbuf* pkt;
  pktmbuf_pool = rte_mempool_lookup (PKTMBUF_POOL_NAME);
  if (pktmbuf_pool == NULL)
  {
    ali_debug_pprint("cannot find pooooool!!!!exit!\n");
    rte_exit (EXIT_FAILURE, "Cannot find mbuf pool!\n");
  }
  pkt = rte_pktmbuf_alloc (pktmbuf_pool);
  a3 = (struct aLTE3 *) rte_pktmbuf_prepend (pkt, sizeof (struct aLTE3));
  a3->messageCode = ALTE3_MESSAGE_CODE;
  a3->imsi = ph->imsi;
  prependIPHeader (pkt, SGW1IP, MME1IP, IP_TYPE_GCONTROL);
  struct onvm_pkt_meta *meta;
  meta =    onvm_get_pkt_meta (pkt);
  meta->destination = LTE_MME1_SERVICE_ID;
  meta->action = ONVM_NF_ACTION_TONF;
  onvm_nflib_return_pkt (pkt);
  ali_debug_pprint ("Req for eps session command alte3 is being sent\n");
  return;
}

void sendLTEH22Response (struct GwOpPlaceHolder* ph) {
#if TIME_LOGGING == ACTIVATED
  clock_gettime(CLOCK_REALTIME, &tl[ph->imsi][TL_H21S]);
#endif

  ali_debug_pprint ("sending response to hlte 21\n");
  struct hLTE22 *h22;
  struct rte_mempool *pktmbuf_pool;
  struct rte_mbuf* pkt;
  pktmbuf_pool = rte_mempool_lookup (PKTMBUF_POOL_NAME);
  if (pktmbuf_pool == NULL)
  {
    ali_debug_pprint("cannot find pooooool!!!!exit!\n");
    rte_exit (EXIT_FAILURE, "Cannot find mbuf pool!\n");
  }
  pkt = rte_pktmbuf_alloc (pktmbuf_pool);
  h22 = (struct hLTE22 *) rte_pktmbuf_prepend (pkt, sizeof (struct hLTE22));
  h22->messageCode = HLTE22_MESSAGE_CODE;
  h22->imsi = ph->imsi;
  prependIPHeader (pkt, SGW1IP, MME1IP, IP_TYPE_GCONTROL);
  struct onvm_pkt_meta *meta;
  meta =    onvm_get_pkt_meta (pkt);
  meta->destination = LTE_MME1_SERVICE_ID;
  meta->action = ONVM_NF_ACTION_TONF;
  onvm_nflib_return_pkt (pkt);
  ali_debug_pprint ("Req for eps session command hlte22 is being sent\n");
  return;
}

void sendLTEH18Response (struct GwOpPlaceHolder* ph) {
#if TIME_LOGGING == ACTIVATED
  clock_gettime(CLOCK_REALTIME, &tl[ph->imsi][TL_H17S]);
#endif

  ali_debug_pprint ("sending response to hlte 17\n");
  struct hLTE18 *h18;
  struct rte_mempool *pktmbuf_pool;
  struct rte_mbuf* pkt;
  pktmbuf_pool = rte_mempool_lookup (PKTMBUF_POOL_NAME);
  if (pktmbuf_pool == NULL)
  {
    ali_debug_pprint("cannot find pooooool!!!!exit!\n");
    rte_exit (EXIT_FAILURE, "Cannot find mbuf pool!\n");
  }
  pkt = rte_pktmbuf_alloc (pktmbuf_pool);
  h18 = (struct hLTE18 *) rte_pktmbuf_prepend (pkt, sizeof (struct hLTE18));
  h18->messageCode = HLTE18_MESSAGE_CODE;
  h18->imsi = ph->imsi;
  prependIPHeader (pkt, SGW1IP, MME1IP, IP_TYPE_GCONTROL);
  struct onvm_pkt_meta *meta;
  meta =    onvm_get_pkt_meta (pkt);
  //meta->destination = LTE_SGW1_SERVICE_ID;
  meta->destination = LTE_MME1_SERVICE_ID;
  meta->action = ONVM_NF_ACTION_TONF;
  onvm_nflib_return_pkt (pkt);
  ali_debug_pprint ("Req for eps session command h18 is being sent\n");
  return;
}


void sendLTE5Response (struct SgwOpLte5* so5) {
#if TIME_LOGGING == ACTIVATED
  clock_gettime(CLOCK_REALTIME, &tl[so5->imsi][TL_T4S]);
#endif

  ali_debug_pprint ("sending response to lte 5\n");
  struct hLTE6 *l6;
  struct rte_mempool *pktmbuf_pool;

  struct rte_mbuf* pkt;
  pktmbuf_pool = rte_mempool_lookup (PKTMBUF_POOL_NAME);
  if (pktmbuf_pool == NULL)
  {
    ali_debug_pprint("cannot find pooooool!!!!exit!\n");
    rte_exit (EXIT_FAILURE, "Cannot find mbuf pool!\n");
  }
  pkt = rte_pktmbuf_alloc (pktmbuf_pool);
  l6 = (struct hLTE6 *) rte_pktmbuf_prepend (pkt, sizeof (struct hLTE6));
  l6->messageCode = HLTE6_MESSAGE_CODE;
  l6->imsi = so5->imsi;
  //l6->ip = so5->ip;
  l6->s1ul = so5->s1ul;
  prependIPHeader (pkt, SGW1IP, MME1IP, IP_TYPE_GCONTROL);
  struct onvm_pkt_meta *meta;
  meta =    onvm_get_pkt_meta (pkt);
  //meta->destination = LTE_SGW1_SERVICE_ID;
  meta->destination = LTE_MME1_SERVICE_ID;
  meta->action = ONVM_NF_ACTION_TONF;
  onvm_nflib_return_pkt (pkt);
  ali_debug_pprint ("Req for eps session command lte6 is being sent\n");
  //meta->action = ONVM_NF_ACTION_DROP;
  return;
}

void sendLTE28Response (struct SgwOpLte28* so28){
#if TIME_LOGGING == ACTIVATED
  clock_gettime(CLOCK_REALTIME, &tl[so28->imsi][TL_T27S]);
#endif

  ali_debug_pprint ("sending response to lte 28\n");
  struct lte28ModRes *lmr28;
  struct rte_mempool *pktmbuf_pool;

  struct rte_mbuf* pkt;
  pktmbuf_pool = rte_mempool_lookup (PKTMBUF_POOL_NAME);
  if (pktmbuf_pool == NULL)
  {
    ali_debug_pprint("cannot find pooooool!!!!exit!\n");
    rte_exit (EXIT_FAILURE, "Cannot find mbuf pool!\n");
  }
  pkt = rte_pktmbuf_alloc (pktmbuf_pool);
  lmr28 = (struct lte28ModRes *) rte_pktmbuf_prepend (pkt, sizeof (struct lte28ModRes));
  lmr28->messageCode = LTE_28_MOD_RES_CODE;
  lmr28->imsi = so28->imsi;
  //ler19->ip = so28->ip;
  //ler19->s1ul = os18->s1ul;
  prependIPHeader (pkt, SGW1IP, MME1IP, IP_TYPE_GCONTROL);
  struct onvm_pkt_meta *meta;
  meta =    onvm_get_pkt_meta (pkt);
  //meta->destination = LTE_SGW1_SERVICE_ID;
  meta->destination = LTE_MME1_SERVICE_ID;
  meta->action = ONVM_NF_ACTION_TONF;
  onvm_nflib_return_pkt (pkt);
  ali_debug_pprint ("Req for eps session command lte28 is being sent\n");
  //meta->action = ONVM_NF_ACTION_DROP;
  return;
}


void sendLTE18Response (struct SgwOpLte18* so18) {
#if TIME_LOGGING == ACTIVATED
  clock_gettime(CLOCK_REALTIME, &tl[so18->imsi][TL_T17S]);
#endif

  ali_debug_pprint ("sending response to lte 18\n");
  struct lte19EpsRes *ler19;
  struct rte_mempool *pktmbuf_pool;

  struct rte_mbuf* pkt;
  pktmbuf_pool = rte_mempool_lookup (PKTMBUF_POOL_NAME);
  if (pktmbuf_pool == NULL)
  {
    ali_debug_pprint("cannot find pooooool!!!!exit!\n");
    rte_exit (EXIT_FAILURE, "Cannot find mbuf pool!\n");
  }
  pkt = rte_pktmbuf_alloc (pktmbuf_pool);
  ler19 = (struct lte19EpsRes *) rte_pktmbuf_prepend (pkt, sizeof (struct lte19EpsRes));
  ler19->messageCode = LTE_19_EPS_RES_CODE;
  if (so18->imsi > USER_STATE_SIZE)
    critical_print ("large imsi size %lu \n", so18->imsi);
  ler19->imsi = so18->imsi;
  ler19->ip = so18->ip;
  ler19->s1ul = so18->s1ul;	
  prependIPHeader (pkt, SGW1IP, MME1IP, IP_TYPE_GCONTROL);
  struct onvm_pkt_meta *meta;
  meta =    onvm_get_pkt_meta (pkt);
  //meta->destination = LTE_SGW1_SERVICE_ID;
  meta->destination = LTE_MME1_SERVICE_ID;
  meta->action = ONVM_NF_ACTION_TONF;
  onvm_nflib_return_pkt (pkt);
  ali_debug_pprint ("Req for eps session command lte19 is being sent\n");
  //meta->action = ONVM_NF_ACTION_DROP;
  return;
}


/*
 * Print a usage message
 */
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
  ali_debug_pprint2 ("a packet received\n");
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
  if (pkt->port == SDN_F4_TOWARD_OF_SERVER) {
    ali_debug_pprint2 ("handle of packet\n");
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
  uint32_t tempSrcIP = rte_be_to_cpu_32 (iph->src_addr);
  //packet is control packet
  if (iph->next_proto_id == IP_TYPE_GUSER)
  {
    ali_debug_pprint ("a data packet received\n");
    // remove the ip header
    rte_pktmbuf_adj (pkt, 20);
    struct GTPUHeader *ge;
    ge = (struct GTPUHeader *) rte_ctrlmbuf_data (pkt);
    // iph->src_addr == rte_be_to_cpu_32(src)
    uint32_t inteid = ge->teid;
    uint32_t outteid;
    //uint32_t tempSrc;
    if (tempSrcIP == ENB1IP)
    {
      //outteid = s1ultos5ul[inteid];
      uint32_t error_stat = 0;
      outteid = retrievestate(s1ultos5ul_hash, inteid, &error_stat);
      if (error_stat == 1) {
	 ali_debug_pprint2("Unfortunatley we had to drop a packet here!\n");
         struct onvm_pkt_meta *pmeta2;
	 pmeta2 = onvm_get_pkt_meta (pkt);
	 pmeta2->action = ONVM_NF_ACTION_DROP;
	 return 0;
      }
      ge->teid = outteid;
      ali_debug_pprint ("before ip\n");
      prependIPHeader (pkt, SGW1IP, PGW1IP, IP_TYPE_GUSER);
      ali_debug_pprint ("data message is being forwarded!\n");
      struct onvm_pkt_meta *pmeta;
      pmeta = onvm_get_pkt_meta (pkt);
      pmeta->destination = LTE_PGW1_SERVICE_ID;
      pmeta->action = ONVM_NF_ACTION_TONF;
#if UTILIZATION_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &lastExitTime);
      totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

      return 0;

    }
    else if (tempSrcIP == PGW1IP)
    {
      //outteid = s5dltos1dl[inteid];
      uint32_t error_stat = 0;
      outteid = retrievestate(s5dltos1dl_hash, inteid, &error_stat);
      if (error_stat == 1) {
	 ali_debug_pprint2("Unfortunatley we had to drop a packet here!\n");
         struct onvm_pkt_meta *pmeta2;
	 pmeta2 = onvm_get_pkt_meta (pkt);
	 pmeta2->action = ONVM_NF_ACTION_DROP;
	 return 0;
      }

      ge->teid = outteid;
      ali_debug_pprint ("before ip\n");
      prependIPHeader (pkt, SGW1IP, ENB1IP, IP_TYPE_GUSER);
      ali_debug_pprint ("data message is being forwarded!\n");
      prependETHF3toF2(pkt); 
      struct onvm_pkt_meta *pmeta;
      pmeta = onvm_get_pkt_meta (pkt);
      pmeta->destination = 0;
      pmeta->action = ONVM_NF_ACTION_OUT;
#if UTILIZATION_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &lastExitTime);
      totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif


      return 0;
    }
    else
    {
      printf("we should never get here for data packet!\n");
#if UTILIZATION_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &lastExitTime);
      totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

      return 0;
    }
  }




  if (iph->next_proto_id == IP_TYPE_GCONTROL)
  {
    ali_debug_pprint ("control packet received\n");
    // remove the ip header
    rte_pktmbuf_adj (pkt, 20);


    if (*rte_ctrlmbuf_data (pkt) == HLTE17_MESSAGE_CODE)
    {
      ali_debug_pprint ("HLTE 17  message received \n");
      struct hLTE17 *l17 = (struct hLTE17 *) rte_ctrlmbuf_data (pkt);
      uint32_t tempImsi = l17->imsi;
#if TIME_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_H17]);
#endif

      struct GwOpPlaceHolder ph;
      ph.messageCode = SGW_OP_H18_CODE;
      ph.imsi = tempImsi;
      sendPacketIn ( &ph, sizeof (struct GwOpPlaceHolder));
      //uint32_t tempTargets1dl = l13->targets1dl;
      //users[tempImsi].targets1dl = tempTargets1dl;
      //s1ulCounter++;
      //uint32_t temps1ul = s1ulCounter;
      //s1ultos5ul[temps1ul] = temps5ul;
      //s1ultos1dl[temps1ul] = indirects1dl;
      /*
	 struct hLTE18 *l18;
	 if (sizeof (struct hLTE18) - sizeof (struct hLTE17) > 0)
	 {                   // more space is needed in the packet
	 rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct hLTE18) - sizeof (struct hLTE17)));
	 ali_debug_pprint2 ("increasing the size\n");
	 }
	 else
	 {                   // the packet is already larger than it shold be
	 rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct hLTE17) - sizeof (struct hLTE18)));
	 ali_debug_pprint2 ("decreasing the size\n");
	 }
	 l18 = (struct hLTE18 *) rte_ctrlmbuf_data (pkt);
	 l18->messageCode = HLTE18_MESSAGE_CODE;
	 l18->imsi = tempImsi;
      //ler19->ip = tempip;
      //l6->s1ul = temps1ul;
      //snprintf ( ar->autn, 256, "%s", "This is autn!" );

      prependIPHeader (pkt, SGW1IP, MME1IP, IP_TYPE_GCONTROL);
      //prependETHF3toF2(pkt);
      meta->destination = LTE_MME1_SERVICE_ID;
      meta->action = ONVM_NF_ACTION_TONF;
      ali_debug_pprint ("hLTE 18 is being sent\n");
      //switch tunnel
      //send end marker
       */
      meta->action = ONVM_NF_ACTION_DROP;
#if UTILIZATION_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &lastExitTime);
      totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

      return 0;
    }
    // ILTE 15
    if (*rte_ctrlmbuf_data (pkt) == ILTE15_MESSAGE_CODE)
    {
      ali_debug_pprint ("ILTE 15  message received \n");
      struct iLTE15 *i15 = (struct iLTE15 *) rte_ctrlmbuf_data (pkt);
      uint32_t tempImsi = i15->imsi;
#if TIME_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_H15]);
#endif

      struct GwOpPlaceHolder ph;
      ph.messageCode = SGW_OP_ITOA_CODE;
      ph.imsi = tempImsi;
      sendPacketIn(&ph, sizeof (struct GwOpPlaceHolder));
      //uint32_t tempTargets1dl = l13->targets1dl;
      //users[tempImsi].targets1dl = tempTargets1dl;
      //s1ulCounter++;
      //uint32_t temps1ul = s1ulCounter;
      //s1ultos5ul[temps1ul] = temps5ul;
      //s1ultos1dl[temps1ul] = indirects1dl;

      /*
	 struct iLTE16 *i16;
	 if (sizeof (struct iLTE16) - sizeof (struct iLTE15) > 0)
	 {                   // more space is needed in the packet
	 rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct iLTE16) - sizeof (struct iLTE15)));
	 ali_debug_pprint2 ("increasing the size\n");
	 }
	 else
	 {                   // the packet is already larger than it shold be
	 rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct iLTE15) - sizeof (struct iLTE16)));
	 ali_debug_pprint2 ("decreasing the size\n");
	 }
	 i16 = (struct iLTE16 *) rte_ctrlmbuf_data (pkt);
	 i16->messageCode = ILTE16_MESSAGE_CODE;
	 i16->imsi = tempImsi;
      //ler19->ip = tempip;
      //l6->s1ul = temps1ul;
      //snprintf ( ar->autn, 256, "%s", "This is autn!" );

      prependIPHeader (pkt, SGW1IP, MME1IP, IP_TYPE_GCONTROL);
      //prependETHF3toF2(pkt);
      meta->destination = LTE_MME1_SERVICE_ID;
      meta->action = ONVM_NF_ACTION_TONF;
      ali_debug_pprint ("iLTE 16 is being sent\n");
      //switch tunnel
      //send end marker
       */
      meta->action = ONVM_NF_ACTION_DROP;
#if UTILIZATION_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &lastExitTime);
      totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

      return 0;
    }

    // dLTE 6
    if (*rte_ctrlmbuf_data (pkt) == DLTE6_MESSAGE_CODE)
    {
      ali_debug_pprint ("DLTE 6  message received \n");
      struct dLTE6 *d6 = (struct dLTE6 *) rte_ctrlmbuf_data (pkt);
      uint32_t tempImsi = d6->imsi;
#if TIME_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_D6]);
#endif

      struct GwOpPlaceHolder ph;
      ph.messageCode = SGW_OP_DETACH_CODE;
      ph.imsi = tempImsi;
      sendPacketIn(&ph, sizeof(struct GwOpPlaceHolder));
      //uint32_t tempTargets1dl = l13->targets1dl;
      //users[tempImsi].targets1dl = tempTargets1dl;
      //s1ulCounter++;
      //uint32_t temps1ul = s1ulCounter;
      //s1ultos5ul[temps1ul] = temps5ul;
      //s1ultos1dl[temps1ul] = indirects1dl;



      /*
	 struct dLTE7 *d7;
	 if (sizeof (struct dLTE7) - sizeof (struct dLTE6) > 0)
	 {                   // more space is needed in the packet
	 rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct dLTE7) - sizeof (struct dLTE6)));
	 ali_debug_pprint2 ("increasing the size\n");
	 }
	 else
	 {                   // the packet is already larger than it shold be
	 rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct dLTE6) - sizeof (struct dLTE7)));
	 ali_debug_pprint2 ("decreasing the size\n");
	 }
	 d7 = (struct dLTE7 *) rte_ctrlmbuf_data (pkt);
	 d7->messageCode = DLTE7_MESSAGE_CODE;
	 d7->imsi = tempImsi;
      //ler19->ip = tempip;
      //l6->s1ul = temps1ul;
      //snprintf ( ar->autn, 256, "%s", "This is autn!" );

      prependIPHeader (pkt, SGW1IP, MME1IP, IP_TYPE_GCONTROL);
      //prependETHF3toF2(pkt);
      meta->destination = LTE_MME1_SERVICE_ID;
      meta->action = ONVM_NF_ACTION_TONF;
      ali_debug_pprint ("dLTE 7 is being sent\n");
      //switch tunnel
      //send end marker
       */
      meta->action = ONVM_NF_ACTION_DROP;
#if UTILIZATION_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &lastExitTime);
      totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

      return 0;
    }
    // aLTE 2
    if (*rte_ctrlmbuf_data (pkt) == ALTE2_MESSAGE_CODE)
    {
      ali_debug_pprint ("ALTE 2  message received \n");
      struct aLTE2 *a2 = (struct aLTE2 *) rte_ctrlmbuf_data (pkt);
      uint32_t tempImsi = a2->imsi;
#if TIME_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_A2]);
#endif

      struct GwOpPlaceHolder ph;
      ph.messageCode = SGW_OP_ATOI_CODE;
      ph.imsi = tempImsi;
      sendPacketIn( &ph, sizeof( struct GwOpPlaceHolder));
      //uint32_t tempTargets1dl = l13->targets1dl;
      //users[tempImsi].targets1dl = tempTargets1dl;
      //s1ulCounter++;
      //uint32_t temps1ul = s1ulCounter;
      //s1ultos5ul[temps1ul] = temps5ul;
      //s1ultos1dl[temps1ul] = indirects1dl;

      /*
	 struct aLTE3 *a3;
	 if (sizeof (struct aLTE3) - sizeof (struct aLTE2) > 0)
	 {                   // more space is needed in the packet
	 rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct aLTE3) - sizeof (struct aLTE2)));
	 ali_debug_pprint2 ("increasing the size\n");
	 }
	 else
	 {                   // the packet is already larger than it shold be
	 rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct aLTE2) - sizeof (struct aLTE3)));
	 ali_debug_pprint2 ("decreasing the size\n");
	 }
	 a3 = (struct aLTE3 *) rte_ctrlmbuf_data (pkt);
	 a3->messageCode = ALTE3_MESSAGE_CODE;
	 a3->imsi = tempImsi;
      //ler19->ip = tempip;
      //l6->s1ul = temps1ul;
      //snprintf ( ar->autn, 256, "%s", "This is autn!" );

      prependIPHeader (pkt, SGW1IP, MME1IP, IP_TYPE_GCONTROL);
      //prependETHF3toF2(pkt);
      meta->destination = LTE_MME1_SERVICE_ID;
      meta->action = ONVM_NF_ACTION_TONF;
      ali_debug_pprint ("aLTE 3 is being sent\n");
      //switch tunnel
      //send end marker
       */
      meta->action = ONVM_NF_ACTION_DROP;
#if UTILIZATION_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &lastExitTime);
      totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

      return 0;
    }


    if (*rte_ctrlmbuf_data (pkt) == HLTE13_MESSAGE_CODE)
    {
      ali_debug_pprint ("HLTE 13  message received \n");
      struct hLTE13 *l13 = (struct hLTE13 *) rte_ctrlmbuf_data (pkt);
      uint32_t tempImsi = l13->imsi;
#if TIME_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_H13]);
#endif

      uint32_t tempTargets1dl = l13->targets1dl;
      //users[tempImsi].targets1dl = tempTargets1dl;
      struct lteSGWUserState* tempUser = retrieveUserState (tempImsi);
      if (tempUser == NULL) {
	//tempUser = addNewKey(tempImsi);
	meta->action = ONVM_NF_ACTION_DROP;
	return 0;
      }
      /*
      if (tempUser == NULL) {
	printf ("we failed in retrieving the key and making a new key \n");
	meta->action = ONVM_NF_ACTION_DROP;
	return 0;
      } else {*/
	tempUser->targets1dl = tempTargets1dl;
      //}




      //s1ulCounter++;
      //uint32_t temps1ul = s1ulCounter;
      //s1ultos5ul[temps1ul] = temps5ul;
      //s1ultos1dl[temps1ul] = indirects1dl;
      struct hLTE14 *l14;
      if (sizeof (struct hLTE14) - sizeof (struct hLTE13) > 0)
      {                   // more space is needed in the packet
	rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct hLTE14) - sizeof (struct hLTE13)));
	ali_debug_pprint2 ("increasing the size\n");
      }
      else
      {                   // the packet is already larger than it shold be
	rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct hLTE13) - sizeof (struct hLTE14)));
	ali_debug_pprint2 ("decreasing the size\n");
      }
      l14 = (struct hLTE14 *) rte_ctrlmbuf_data (pkt);
      l14->messageCode = HLTE14_MESSAGE_CODE;
      l14->imsi = tempImsi;
      //ler19->ip = tempip;
      //l6->s1ul = temps1ul;
      //snprintf ( ar->autn, 256, "%s", "This is autn!" );

      prependIPHeader (pkt, SGW1IP, PGW1IP, IP_TYPE_GCONTROL);
      //prependETHF3toF2(pkt);
      meta->destination = LTE_PGW1_SERVICE_ID;
      meta->action = ONVM_NF_ACTION_TONF;
      ali_debug_pprint ("hLTE 14 is being sent\n");
#if UTILIZATION_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &lastExitTime);
      totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

      return 0;
    }
    // ilte 11
    if (*rte_ctrlmbuf_data (pkt) == ILTE11_MESSAGE_CODE)
    {
      ali_debug_pprint ("ilte 11  message received \n");
      struct iLTE11 *i11 = (struct iLTE11 *) rte_ctrlmbuf_data (pkt);
      uint32_t tempImsi = i11->imsi;
#if TIME_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_I11]);
#endif

      //uint32_t tempTargets1dl = l13->targets1dl;
      //users[tempImsi].targets1dl = tempTargets1dl;
      //s1ulCounter++;
      //uint32_t temps1ul = s1ulCounter;
      //s1ultos5ul[temps1ul] = temps5ul;
      //s1ultos1dl[temps1ul] = indirects1dl;
      struct iLTE12 *i12;
      if (sizeof (struct iLTE12) - sizeof (struct iLTE11) > 0)
      {                   // more space is needed in the packet
	rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct iLTE12) - sizeof (struct iLTE11)));
	ali_debug_pprint2 ("increasing the size\n");
      }
      else
      {                   // the packet is already larger than it shold be
	rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct iLTE11) - sizeof (struct iLTE12)));
	ali_debug_pprint2 ("decreasing the size\n");
      }
      i12 = (struct iLTE12 *) rte_ctrlmbuf_data (pkt);
      i12->messageCode = ILTE12_MESSAGE_CODE;
      i12->imsi = tempImsi;
      //ler19->ip = tempip;
      //l6->s1ul = temps1ul;
      //snprintf ( ar->autn, 256, "%s", "This is autn!" );

      prependIPHeader (pkt, SGW1IP, PGW1IP, IP_TYPE_GCONTROL);
      //prependETHF3toF2(pkt);
      meta->destination = LTE_PGW1_SERVICE_ID;
      meta->action = ONVM_NF_ACTION_TONF;
      ali_debug_pprint ("iLTE 12 is being sent\n");
#if UTILIZATION_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &lastExitTime);
      totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

      return 0;
    }
    // dlte 2
    if (*rte_ctrlmbuf_data (pkt) == DLTE2_MESSAGE_CODE)
    {
      ali_debug_pprint ("dlate 2  message received \n");
      struct dLTE2 *d2 = (struct dLTE2 *) rte_ctrlmbuf_data (pkt);
      uint32_t tempImsi = d2->imsi;
#if TIME_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_D2]);
#endif

      //uint32_t tempTargets1dl = l13->targets1dl;
      //users[tempImsi].targets1dl = tempTargets1dl;
      //s1ulCounter++;
      //uint32_t temps1ul = s1ulCounter;
      //s1ultos5ul[temps1ul] = temps5ul;
      //s1ultos1dl[temps1ul] = indirects1dl;
      struct dLTE3 *d3;
      if (sizeof (struct dLTE3) - sizeof (struct dLTE2) > 0)
      {                   // more space is needed in the packet
	rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct dLTE3) - sizeof (struct dLTE2)));
	ali_debug_pprint2 ("increasing the size\n");
      }
      else
      {                   // the packet is already larger than it shold be
	rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct dLTE2) - sizeof (struct dLTE3)));
	ali_debug_pprint2 ("decreasing the size\n");
      }
      d3 = (struct dLTE3 *) rte_ctrlmbuf_data (pkt);
      d3->messageCode = DLTE3_MESSAGE_CODE;
      d3->imsi = tempImsi;
      //ler19->ip = tempip;
      //l6->s1ul = temps1ul;
      //snprintf ( ar->autn, 256, "%s", "This is autn!" );

      prependIPHeader (pkt, SGW1IP, PGW1IP, IP_TYPE_GCONTROL);
      //prependETHF3toF2(pkt);
      meta->destination = LTE_PGW1_SERVICE_ID;
      meta->action = ONVM_NF_ACTION_TONF;
      ali_debug_pprint ("dLTE 3 is being sent\n");
#if UTILIZATION_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &lastExitTime);
      totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

      return 0;
    }

    if (*rte_ctrlmbuf_data (pkt) == HLTE21_MESSAGE_CODE)
    {
      ali_debug_pprint ("HLTE 21  message received \n");
      struct hLTE21 *l21 = (struct hLTE21 *) rte_ctrlmbuf_data (pkt);
      uint32_t tempImsi = l21->imsi;
#if TIME_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_H21]);
#endif

      struct GwOpPlaceHolder ph;
      ph.messageCode = SGW_OP_H22_CODE;
      ph.imsi = tempImsi;
      sendPacketIn ( &ph, sizeof (struct GwOpPlaceHolder));
      //uint32_t tempTargets1dl = l21->targets1dl;
      //users[tempImsi].targets1dl = tempTargets1dl;
      //s1ulCounter++;
      //uint32_t temps1ul = s1ulCounter;
      //s1ultos5ul[temps1ul] = temps5ul;
      //s1ultos1dl[temps1ul] = indirects1dl;
      /*
	 struct hLTE22 *l22;
	 if (sizeof (struct hLTE22) - sizeof (struct hLTE21) > 0)
	 {                   // more space is needed in the packet
	 rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct hLTE22) - sizeof (struct hLTE21)));
	 ali_debug_pprint2 ("increasing the size\n");
	 }
	 else
	 {                   // the packet is already larger than it shold be
	 rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct hLTE21) - sizeof (struct hLTE22)));
	 ali_debug_pprint2 ("decreasing the size\n");
	 }
	 l22 = (struct hLTE22 *) rte_ctrlmbuf_data (pkt);
	 l22->messageCode = HLTE22_MESSAGE_CODE;
	 l22->imsi = tempImsi;
      //ler19->ip = tempip;
      //l6->s1ul = temps1ul;
      //snprintf ( ar->autn, 256, "%s", "This is autn!" );

      prependIPHeader (pkt, SGW1IP, MME1IP, IP_TYPE_GCONTROL);
      //prependETHF3toF2(pkt);
      meta->destination = LTE_MME1_SERVICE_ID;
      meta->action = ONVM_NF_ACTION_TONF;
      ali_debug_pprint ("hLTE 22 is being sent\n");
       */
      meta->action = ONVM_NF_ACTION_DROP;
#if UTILIZATION_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &lastExitTime);
      totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

      return 0;
    }


    if (*rte_ctrlmbuf_data (pkt) == HLTE5_MESSAGE_CODE)
    {
      ali_debug_pprint ("HLTE5  message received \n");
      struct hLTE5 *l5 = (struct hLTE5 *) rte_ctrlmbuf_data (pkt);
      uint32_t tempImsi = l5->imsi;
#if TIME_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_H5]);
#endif

      uint32_t indirects1dl = l5->indirects1dl;
      s1ulCounter++;
      uint32_t temps1ul = s1ulCounter;
      //s1ultos5ul[temps1ul] = temps5ul;
      //s1ultos1dl[temps1ul] = indirects1dl;
      setState (s1ultos1dl_hash, temps1ul,indirects1dl);
      struct SgwOpLte5 so5;
      so5.messageCode = SGW_OP_LTE5_CODE;
      so5.imsi = tempImsi;
      so5.s1ul = temps1ul;
      so5.s1dl = indirects1dl;
      //so28.s5dl = users[tempImsi].s5dl;
      sendPacketIn(&so5, sizeof(struct SgwOpLte5));


      /*struct hLTE6 *l6;
	if (sizeof (struct hLTE6) - sizeof (struct hLTE5) > 0)
	{                   // more space is needed in the packet
	rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct hLTE6) - sizeof (struct hLTE5)));
	ali_debug_pprint2 ("increasing the size\n");
	}
	else
	{                   // the packet is already larger than it shold be
	rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct hLTE5) - sizeof (struct hLTE6)));
	ali_debug_pprint2 ("decreasing the size\n");
	}
	l6 = (struct hLTE6 *) rte_ctrlmbuf_data (pkt);
	l6->messageCode = HLTE6_MESSAGE_CODE;
	l6->imsi = tempImsi;
      //ler19->ip = tempip;
      l6->s1ul = temps1ul;
      //snprintf ( ar->autn, 256, "%s", "This is autn!" );

      prependIPHeader (pkt, SGW1IP, MME1IP, IP_TYPE_GCONTROL);
      //prependETHF3toF2(pkt);
      meta->destination = LTE_MME1_SERVICE_ID;
      meta->action = ONVM_NF_ACTION_TONF;
      ali_debug_pprint ("hLTE6 is being sent\n");*/
      meta->action = ONVM_NF_ACTION_DROP;
#if UTILIZATION_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &lastExitTime);
      totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

      return 0;
    }
    if (*rte_ctrlmbuf_data (pkt) == LTE_12_EPS_REQ_CODE)
    {

      ali_debug_pprint ("a eps req code  message received \n");
      struct lte12EpsReq *ler12 = (struct lte12EpsReq *) rte_ctrlmbuf_data (pkt);
      uint32_t tempImsi = ler12->imsi;
#if TIME_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_T12]);
#endif

      if (tempImsi > USER_STATE_SIZE)
	critical_print ("large imsi! %u\n", tempImsi);

      struct lte13EpsReq *ler13;
      if (sizeof (struct lte13EpsReq) - sizeof (struct lte12EpsReq) > 0)
      {			// more space is needed in the packet
	rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct lte13EpsReq) - sizeof (struct lte12EpsReq)));
	ali_debug_pprint ("increasing the size\n");
      }
      else
      {			// the packet is already larger than it shold be
	rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct lte12EpsReq) - sizeof (struct lte13EpsReq)));
	ali_debug_pprint ("decreasing the size\n");
      }
      ler13 = (struct lte13EpsReq *) rte_ctrlmbuf_data (pkt);
      ler13->messageCode = LTE_13_EPS_REQ_CODE;
      ler13->imsi = tempImsi;
      ler13->s5dl = s5dlCounter;
      //set user s5dl here
      //users[tempImsi].s5dl = s5dlCounter;
      struct lteSGWUserState* tempUser = retrieveUserState (tempImsi);
      if (tempUser == NULL) {
	tempUser = addNewKey(tempImsi);
      }
      if (tempUser == NULL) {
	printf ("we failed in retrieving the key and making a new key \n");
	meta->action = ONVM_NF_ACTION_DROP;
	return 0;
      } else {
	tempUser->s5dl = s5dlCounter;
      }


      s5dlCounter++;
      //snprintf ( ar->autn, 256, "%s", "This is autn!" );

      prependIPHeader (pkt, SGW1IP, PGW1IP, IP_TYPE_GCONTROL);
      //prependETHF3toF2(pkt);
      meta->destination = LTE_PGW1_SERVICE_ID;
      meta->action = ONVM_NF_ACTION_TONF;
      ali_debug_pprint ("Req for eps session command is being sent\n");
#if UTILIZATION_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &lastExitTime);
      totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

      return 0;
    }
    if (*rte_ctrlmbuf_data (pkt) == LTE_18_EPS_RES_CODE)
    {
      ali_debug_pprint ("a eps res  message received \n");
      struct lte18EpsRes *ler18 = (struct lte18EpsRes *) rte_ctrlmbuf_data (pkt);
      uint32_t tempImsi = ler18->imsi;
#if TIME_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_T18]);
#endif

      if (tempImsi > USER_STATE_SIZE)
	critical_print ("large imsi! %u\n", tempImsi);
      uint32_t tempip = ler18->ip;
      uint32_t temps5ul = ler18->s5ul;
      uint32_t temps1ul = s1ulCounter;
      s1ulCounter++;
      //s1ultos5ul[temps1ul] = temps5ul;
      setState(s1ultos5ul_hash, temps1ul,temps5ul);

      struct SgwOpLte18 so18;
      so18.messageCode = SGW_OP_LTE18_CODE;
      so18.ip = tempip;
      so18.s1ul = temps1ul;
      so18.s5ul = temps5ul;
      so18.imsi = tempImsi;
      sendPacketIn(&so18, sizeof (struct SgwOpLte18));
      /*
	 struct lte19EpsRes *ler19;
	 if (sizeof (struct lte19EpsRes) - sizeof (struct lte18EpsRes) > 0)
	 {			// more space is needed in the packet
	 rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct lte19EpsRes) - sizeof (struct lte18EpsRes)));
	 ali_debug_pprint ("increasing the size\n");
	 }
	 else
	 {			// the packet is already larger than it shold be
	 rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct lte18EpsRes) - sizeof (struct lte19EpsRes)));
	 ali_debug_pprint ("decreasing the size\n");
	 }
	 ler19 = (struct lte19EpsRes *) rte_ctrlmbuf_data (pkt);
	 ler19->messageCode = LTE_19_EPS_RES_CODE;
	 ler19->imsi = tempImsi;
	 ler19->ip = tempip;
	 ler19->s1ul = temps1ul;
      //snprintf ( ar->autn, 256, "%s", "This is autn!" );

      prependIPHeader (pkt, SGW1IP, MME1IP, IP_TYPE_GCONTROL);
      //prependETHF3toF2(pkt);
      meta->destination = LTE_MME1_SERVICE_ID;
      meta->action = ONVM_NF_ACTION_TONF;
      ali_debug_pprint ("eps session creation response is being sent\n");*/
      meta->action = ONVM_NF_ACTION_DROP;
#if UTILIZATION_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &lastExitTime);
      totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

      return 0;
    }
    //lte27BrearerMod,lte28ModRes,,LTE_27_BEARER_MOD_CODE,LTE_28_MOD_RES_CODE
    if (*rte_ctrlmbuf_data (pkt) == LTE_27_BEARER_MOD_CODE)
    {
      ali_debug_pprint ("27  message received \n");
      struct lte27BrearerMod *lbm = (struct lte27BrearerMod *) rte_ctrlmbuf_data (pkt);
      uint32_t tempImsi = lbm->imsi;
#if TIME_LOGGING == ACTIVATED
      clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_T27]);
#endif

      uint32_t temps1dl = lbm->s1dl;
      //s5dltos1dl[users[tempImsi].s5dl] = temps1dl;
      //setState(s5dltos1dl_hash, users[tempImsi].s5dl, temps1dl);
      uint32_t key = 0;//users[tempImsi].s5dl;

      struct lteSGWUserState* tempUser = retrieveUserState (tempImsi);
      if (tempUser == NULL) {
	tempUser = addNewKey(tempImsi);
      }
      if (tempUser == NULL) {
	printf ("we failed in retrieving the key and making a new key \n");
	meta->action = ONVM_NF_ACTION_DROP;
	return 0;
      } else {
	key = tempUser->s5dl;
      }

      setState (s5dltos1dl_hash, key, temps1dl);

      struct SgwOpLte28 so28;
      so28.messageCode = SGW_OP_LTE28_CODE;
      so28.imsi = tempImsi;
      so28.s1dl = temps1dl;
      
      so28.s5dl = key;
      
      sendPacketIn(&so28, sizeof(struct SgwOpLte28));

      /*	struct lte28ModRes *lmr;
		if (sizeof (struct lte28ModRes) - sizeof (struct lte27BrearerMod) > 0)
		{			// more space is needed in the packet
		rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct lte28ModRes) - sizeof (struct lte27BrearerMod)));
		ali_debug_pprint ("increasing the size\n");
		}
		else
		{			// the packet is already larger than it shold be
		rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct lte27BrearerMod) - sizeof (struct lte28ModRes)));
		ali_debug_pprint ("decreasing the size\n");
		}
		lmr = (struct lte28ModRes *) rte_ctrlmbuf_data (pkt);
		lmr->messageCode = LTE_28_MOD_RES_CODE;
		lmr->imsi = tempImsi;
      //snprintf ( ar->autn, 256, "%s", "This is autn!" );

      prependIPHeader (pkt, SGW1IP, MME1IP, IP_TYPE_GCONTROL);
      //prependETHF3toF2(pkt);
      meta->destination = LTE_MME1_SERVICE_ID;
      meta->action = ONVM_NF_ACTION_TONF;
      ali_debug_pprint ("28 is being sent\n");*/
      meta->action = ONVM_NF_ACTION_DROP;
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
  ali_debug_pprint("before setting hash parametres\n");
  struct rte_hash_parameters s1s5_hash_params = {
    .name = "s1s5Hash",
    .entries = USER_STATE_SIZE,
    .key_len = sizeof(uint32_t),
    .hash_func = DEFAULT_HASH_FUNC,
    .hash_func_init_val = 0,
    .socket_id = rte_socket_id(),
  };
  ali_debug_pprint("after setting hash parameteres, before creating hash\n");
  s1ultos5ul_hash = rte_hash_create(&s1s5_hash_params);
  if (s1ultos5ul_hash == NULL) {
    critical_pprint("unable to make the hash!!\n");
  }
  ali_debug_pprint("hash created successfully\n");

  ali_debug_pprint("before setting hash parametres\n");
  struct rte_hash_parameters s1s1_hash_params = {
    .name = "s1s1Hash",
    .entries = USER_STATE_SIZE,
    .key_len = sizeof(uint32_t),
    .hash_func = DEFAULT_HASH_FUNC,
    .hash_func_init_val = 0,
    .socket_id = rte_socket_id(),
  };
  ali_debug_pprint("after setting hash parameteres, before creating hash\n");
  s1ultos1dl_hash = rte_hash_create(&s1s1_hash_params);
  if (s1ultos1dl_hash == NULL) {
    critical_pprint("unable to make the hash!!\n");
  }
  ali_debug_pprint("hash created successfully\n");

  ali_debug_pprint("before setting hash parametres\n");
  struct rte_hash_parameters s5s1_hash_params = {
    .name = "s5s1Hash",
    .entries = USER_STATE_SIZE,
    .key_len = sizeof(uint32_t),
    .hash_func = DEFAULT_HASH_FUNC,
    .hash_func_init_val = 0,
    .socket_id = rte_socket_id(),
  };
  ali_debug_pprint("after setting hash parameteres, before creating hash\n");
  s5dltos1dl_hash = rte_hash_create(&s5s1_hash_params);
  if (s5dltos1dl_hash == NULL) {
    critical_pprint("unable to make the hash!!\n");
  }
  ali_debug_pprint("hash created successfully\n");
  ali_debug_pprint("before setting hash parametres\n");
  struct rte_hash_parameters users_hash_params = {
    .name = "sgwUserHash",
    .entries = USER_STATE_SIZE,
    .key_len = sizeof(uint32_t),
    .hash_func = DEFAULT_HASH_FUNC,
    .hash_func_init_val = 0,
    .socket_id = rte_socket_id(),
  };
  ali_debug_pprint("after setting hash parameteres, before creating hash\n");
  users_hash = rte_hash_create(&users_hash_params);
  if (users_hash == NULL) {
    critical_pprint("unable to make the hash!!\n");
  }
  ali_debug_pprint("hash created successfully\n");





  onvm_nflib_run (nf_info, &packet_handler);
#if UTILIZATION_LOGGING == ACTIVATED
  recordUtilizationLog ("ULogf4sgw.txt", utilization);
#endif
#if TIME_LOGGING == ACTIVATED
  writeTimeLogToFile ("f4sgw.txt", tl);
#endif
  printf ("If we reach here, program is ending");
  return 0;
}
