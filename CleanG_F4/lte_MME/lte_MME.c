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

/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

/* number of package between each print */
static uint32_t print_delay = 1000000;

#if UTILIZATION_LOGGING == ACTIVATED
long long lastRecordedSecond = 0;
//static struct timespec lastStartPeriod;
static struct timespec lastExitTime;
static unsigned long totalActiveTimeInLastPeriod;
//static unsigned long totalIdleTimeInLastPeriod;
// It is is not started with zero. current_time_second % MAXIMUM_RUN_TIME_IN_SECONDS is used for storage
static double utilization [MAXIMUM_RUN_TIME_IN_SECONDS];
#endif

static uint32_t destination;

#if TIME_LOGGING == ACTIVATED
//static struct timeLoggingState tl[NUMBER_OF_USERS];
#if NUMBER_OF_USERS > 100000
#warning "When TIME_LOGGING is activated, number of users cannot be very large\n"
#endif

static struct timespec tl[NUMBER_OF_USERS][MAX_NUMBER_OF_MESSAGE_CODES];
#define TL_T3  0
#define TL_T7  1
#define TL_T9  2
#define TL_T19 3
#define TL_T25 4
#define TL_T26 6
#define TL_T28 7
#define TL_A1  8
#define TL_A3  9
#define TL_A6  10
#define TL_I3  11
#define TL_I10 12
#define TL_I16 13
#define TL_D1  14
#define TL_D7  15
#define TL_D11 16
#define TL_H2  17
#define TL_H4  18
#define TL_H6  19
#define TL_H9  20
#define TL_H12 21
#define TL_H18 22
#define TL_H20 23
#define TL_H22 24
#endif
//static struct lteMMEUserState users[USER_STATE_SIZE];
static struct rte_hash* users_hash;

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

static struct lteMMEUserState* retrievestate (uint32_t hashKey) {
  struct lteMMEUserState * hashValue = NULL;
  int lookup_code = rte_hash_lookup_data (users_hash, &hashKey,(void**) &hashValue);
  ali_debug_print("look up code is %d\n",lookup_code);
  // TODO: It seems the Api's document is not ritht! and this function returns the place in the hash!
  if (lookup_code < 0) {
    critical_pprint("problem in hash table look up!\n");
    critical_print("look up code is: %d \n", lookup_code);
    if (hashValue != NULL) {
      critical_pprint ("hashValue is not null but code is negative\n");
    } else {
      critical_pprint ("enbIP is NULL!\n");
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
    critical_pprint("Entry does not exist in the hash\n");
    return NULL;
  }
  if (hashValue == NULL) {
    critical_pprint ("Couldn't get the proper enbIP from hash table\n");
    // TODO: This return zero is a temporary fix! it is not right to do it.
    return NULL;
  } else {
    return hashValue;
  }
}

static struct lteMMEUserState* addNewKey (uint32_t key) {
  struct lteMMEUserState* valuePointer = rte_malloc( "uint32_t", sizeof (struct lteMMEUserState), 0);
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
    // There is a trade of in using total idel time. by using total idle time we could double check for correctness, but it added computation and also could give false alarm for the first time.
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
  if (++counter == print_delay && PACKET_COUNTER_STATS == ACTIVATED)
  {
    do_stats_display (pkt);
    counter = 0;
  }
  //struct ipv4_hdr *iph;
  //iph = (struct ipv4_hdr *) rte_ctrlmbuf_data (pkt);
  //packe is from eNodeB1
  //	if (iph->src_addr == rte_be_to_cpu_32 (ENB2IP))
  //	{
  //		ali_debug_pprint ("packet received from enb 2\n");
  rte_pktmbuf_adj (pkt, 20);
  if (*rte_ctrlmbuf_data (pkt) == HLTE4_MESSAGE_CODE)        // it is an attach command
  {
    ali_debug_pprint ("hlte4 message received \n");
    struct hLTE4 *l4 = (struct hLTE4 *) rte_ctrlmbuf_data (pkt);
    uint32_t tempImsi = l4->imsi;
#if TIME_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_H4]);
#endif
    uint32_t temps1dl = l4->s1dl;
    if (tempImsi <USER_STATE_SIZE){
      //users[tempImsi].targets1dl = temps1dl;
      struct lteMMEUserState* user = NULL;
      user = retrievestate(tempImsi);
      if (user == NULL) {
	user = addNewKey (tempImsi);
      }
      if (user == NULL) {
	printf ("we failed in retrieving a key or making a new key!\n");
	meta->action = ONVM_NF_ACTION_DROP;
	return 0;
      } else {
	user->targets1dl = temps1dl;
      }

    } else {
      printf ("problem1!!! tempImsi is out of range! %u \n", tempImsi);
    }
    uint32_t tempindirects1dl = l4->indirects1dl;
    struct hLTE5 *l5;

    if (sizeof (struct hLTE5) - sizeof (struct hLTE4) > 0)
    {                   // more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct hLTE5) - sizeof (struct hLTE4)));
      ali_debug_pprint2 ("increasing the size\n");
    }
    else
    {                   // the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct hLTE4) - sizeof (struct hLTE5)));
      ali_debug_pprint2 ("decreasing the size\n");
    }

    l5 = (struct hLTE5 *) rte_ctrlmbuf_data (pkt);
    l5->messageCode = HLTE5_MESSAGE_CODE;
    l5->imsi = tempImsi;
    l5->indirects1dl = tempindirects1dl;
    //l3->ip = users[tempImsi].ip;
    //snprintf (ar->autn, 256, "%s", "This is autn!");

    prependIPHeader (pkt, MME1IP, SGW1IP, IP_TYPE_GCONTROL);
    //prependETHF4toF3 (pkt);
    meta->destination = LTE_SGW1_SERVICE_ID;
    meta->action = ONVM_NF_ACTION_TONF;
    ali_debug_pprint ("hlte5 is being sent\n");
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif
    return 0;
  }
  if (*rte_ctrlmbuf_data (pkt) == HLTE12_MESSAGE_CODE)        // it is an attach command
  {
    ali_debug_pprint ("hlte 12 message received \n");
    struct hLTE12 *l12 = (struct hLTE12 *) rte_ctrlmbuf_data (pkt);
    uint32_t tempImsi = l12->imsi;
#if TIME_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_H12]);
#endif

    //uint32_t temps1dl = l4->s1dl;
    //users[tempImsi].targets1dl = temps1dl;
    //uint32_t tempindirects1dl = l4->indirects1dl;
    struct hLTE13 *l13;

    if (sizeof (struct hLTE13) - sizeof (struct hLTE12) > 0)
    {                   // more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct hLTE13) - sizeof (struct hLTE12)));
      ali_debug_pprint2 ("increasing the size\n");
    }
    else
    {                   // the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct hLTE12) - sizeof (struct hLTE13)));
      ali_debug_pprint2 ("decreasing the size\n");
    }

    l13 = (struct hLTE13 *) rte_ctrlmbuf_data (pkt);
    l13->messageCode = HLTE13_MESSAGE_CODE;
    l13->imsi = tempImsi;
    if ( tempImsi <USER_STATE_SIZE){
      //	           users[tempImsi].targets1dl = temps1dl;
      //l13->targets1dl = users[tempImsi].targets1dl;
      struct lteMMEUserState* user = NULL;
      user = retrievestate(tempImsi);
      if (user == NULL) {
	printf ("failed to retrieve the key!\n");
	meta->action = ONVM_NF_ACTION_DROP;
	return 0;

      } else {
	l13->targets1dl = user->targets1dl;
      }

    } else {
      printf ("problem2!!! tempImsi is out of range! %u \n", tempImsi);
    }
    //l5->indirects1dl = tempindirects1dl;
    //l3->ip = users[tempImsi].ip;
    //snprintf (ar->autn, 256, "%s", "This is autn!");

    prependIPHeader (pkt, MME1IP, SGW1IP, IP_TYPE_GCONTROL);
    //prependETHF4toF3 (pkt);
    meta->destination = LTE_SGW1_SERVICE_ID;
    meta->action = ONVM_NF_ACTION_TONF;
    ali_debug_pprint ("hlte 13 is being sent\n");
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }

  if (*rte_ctrlmbuf_data (pkt) == HLTE20_MESSAGE_CODE)
  {
    ali_debug_pprint ("hlte 20 message received \n");
    struct hLTE20 *l20 = (struct hLTE20 *) rte_ctrlmbuf_data (pkt);
    uint32_t tempImsi = l20->imsi;
#if TIME_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_H20]);
#endif

    //uint32_t temps1dl = l4->s1dl;
    //users[tempImsi].targets1dl = temps1dl;
    //uint32_t tempindirects1dl = l4->indirects1dl;
    struct hLTE21 *l21;

    if (sizeof (struct hLTE21) - sizeof (struct hLTE20) > 0)
    {                   // more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct hLTE21) - sizeof (struct hLTE20)));
      ali_debug_pprint2 ("increasing the size\n");
    }
    else
    {                   // the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct hLTE20) - sizeof (struct hLTE21)));
      ali_debug_pprint2 ("decreasing the size\n");
    }

    l21 = (struct hLTE21 *) rte_ctrlmbuf_data (pkt);
    l21->messageCode = HLTE21_MESSAGE_CODE;
    l21->imsi = tempImsi;
    //l21->targets1dl = users[tempImsi].targets1dl;
    //l5->indirects1dl = tempindirects1dl;
    //l3->ip = users[tempImsi].ip;
    //snprintf (ar->autn, 256, "%s", "This is autn!");

    prependIPHeader (pkt, MME1IP, SGW1IP, IP_TYPE_GCONTROL);
    //prependETHF4toF3 (pkt);
    meta->destination = LTE_SGW1_SERVICE_ID;
    meta->action = ONVM_NF_ACTION_TONF;
    ali_debug_pprint ("hlte 21 is being sent\n");
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }

  if (*rte_ctrlmbuf_data (pkt) == HLTE18_MESSAGE_CODE)        // it is an attach command
  {
    ali_debug_pprint ("hlte 18 message received \n");
    struct hLTE18 *l18 = (struct hLTE18 *) rte_ctrlmbuf_data (pkt);
    uint32_t tempImsi = l18->imsi;
#if TIME_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_H18]);
#endif

    //uint32_t temps1dl = l4->s1dl;
    //users[tempImsi].targets1dl = temps1dl;
    //uint32_t tempindirects1dl = l4->indirects1dl;
    struct hLTE19 *l19;

    if (sizeof (struct hLTE19) - sizeof (struct hLTE18) > 0)
    {                   // more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct hLTE19) - sizeof (struct hLTE18)));
      ali_debug_pprint2 ("increasing the size\n");
    }
    else
    {                   // the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct hLTE18) - sizeof (struct hLTE19)));
      ali_debug_pprint2 ("decreasing the size\n");
    }

    l19 = (struct hLTE19 *) rte_ctrlmbuf_data (pkt);
    l19->messageCode = HLTE19_MESSAGE_CODE;
    l19->imsi = tempImsi;
    //l13->targets1dl = users[tempImsi].targets1dl;
    //l5->indirects1dl = tempindirects1dl;
    //l3->ip = users[tempImsi].ip;
    //snprintf (ar->autn, 256, "%s", "This is autn!");

    prependIPHeader (pkt, MME1IP, ENB1IP, IP_TYPE_GCONTROL);
    prependETHF4toF3 (pkt);
    meta->destination = SDN_F4_TOWARD_DATA_PORT;
    meta->action = ONVM_NF_ACTION_OUT;
    ali_debug_pprint ("hlte 19 is being sent\n");
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }
  // a3

  if (*rte_ctrlmbuf_data (pkt) == HLTE22_MESSAGE_CODE)        // it is an attach command
  {
    ali_debug_pprint ("hlte 22 message received \n");
    struct hLTE22 *l22 = (struct hLTE22 *) rte_ctrlmbuf_data (pkt);
    uint32_t tempImsi = l22->imsi;
#if TIME_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_H22]);
#endif

    struct hLTE23 *l23;

    if (sizeof (struct hLTE23) - sizeof (struct hLTE22) > 0)
    {                   // more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct hLTE23) - sizeof (struct hLTE22)));
      ali_debug_pprint2 ("increasing the size\n");
    }
    else
    {                   // the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct hLTE22) - sizeof (struct hLTE23)));
      ali_debug_pprint2 ("decreasing the size\n");
    }

    l23 = (struct hLTE23 *) rte_ctrlmbuf_data (pkt);
    l23->messageCode = HLTE23_MESSAGE_CODE;
    l23->imsi = tempImsi;
    //l13->targets1dl = users[tempImsi].targets1dl;
    //l5->indirects1dl = tempindirects1dl;
    //l3->ip = users[tempImsi].ip;
    //snprintf (ar->autn, 256, "%s", "This is autn!");

    prependIPHeader (pkt, MME1IP, ENB1IP, IP_TYPE_GCONTROL);
    prependETHF4toF3 (pkt);
    meta->destination = SDN_F4_TOWARD_DATA_PORT;
    meta->action = ONVM_NF_ACTION_OUT;
    ali_debug_pprint ("hlte 23 is being sent\n");
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }

  //	}

  //	if (iph->src_addr == rte_be_to_cpu_32 (ENB1IP))
  //	{
  //		ali_debug_pprint ("packet received from enb 1\n");
  //		// remove the ip header
  //		rte_pktmbuf_adj (pkt, 20);

  if (*rte_ctrlmbuf_data (pkt) == HLTE9_MESSAGE_CODE)        // it is an attach command
  {
    ali_debug_pprint ("hlte9 message received \n");
    struct hLTE9 *l9 = (struct hLTE9 *) rte_ctrlmbuf_data (pkt);
    uint32_t tempImsi = l9->imsi;
#if TIME_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_H9]);
#endif

    struct hLTE10 *l10;

    if (sizeof (struct hLTE10) - sizeof (struct hLTE9) > 0)
    {                   // more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct hLTE10) - sizeof (struct hLTE9)));
      ali_debug_pprint2 ("increasing the size\n");
    }
    else
    {                   // the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct hLTE10) - sizeof (struct hLTE9)));
      ali_debug_pprint2 ("decreasing the size\n");
    }

    l10 = (struct hLTE10 *) rte_ctrlmbuf_data (pkt);
    l10->messageCode = HLTE10_MESSAGE_CODE;
    l10->imsi = tempImsi;
    //l3->ip = users[tempImsi].ip;
    //snprintf (ar->autn, 256, "%s", "This is autn!");

    prependIPHeader (pkt, MME1IP, ENB2IP, IP_TYPE_NAS);
    prependETHF4toF3 (pkt);
    meta->destination = SDN_F4_TOWARD_DATA_PORT;
    meta->action = ONVM_NF_ACTION_OUT;
    ali_debug_pprint ("hlte10 is being sent\n");
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }



  if (*rte_ctrlmbuf_data (pkt) == HLTE2_MESSAGE_CODE)        // it is an attach command
  {
    ali_debug_pprint ("hlte2 message received \n");
    struct hLTE2 *l2 = (struct hLTE2 *) rte_ctrlmbuf_data (pkt);
    uint32_t tempImsi = l2->imsi;
#if TIME_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_H2]);
#endif

    struct hLTE3 *l3;

    if (sizeof (struct hLTE3) - sizeof (struct hLTE2) > 0)
    {                   // more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct hLTE3) - sizeof (struct hLTE2)));
      ali_debug_pprint2 ("increasing the size\n");
    }
    else
    {                   // the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct hLTE2) - sizeof (struct hLTE3)));
      ali_debug_pprint2 ("decreasing the size\n");
    }

    l3 = (struct hLTE3 *) rte_ctrlmbuf_data (pkt);
    l3->messageCode = HLTE3_MESSAGE_CODE;
    l3->imsi = tempImsi;
    if ( tempImsi <USER_STATE_SIZE){
      //		                  users[tempImsi].targets1dl = temps1dl;
      //l3->ip = users[tempImsi].ip;
      struct lteMMEUserState* user = NULL;
      user = retrievestate(tempImsi);
      if (user == NULL) {
	printf ("failed to retrieve the key!\n");
	meta->action = ONVM_NF_ACTION_DROP;
	return 0;

      } else {
	l3->ip = user->ip;
      }


    } else {
      printf ("problem3!!! tempImsi is out of range! %u \n", tempImsi);
    }
    ali_debug_print ("hlte3 ip is %u \n", l3->ip);
    //snprintf (ar->autn, 256, "%s", "This is autn!");

    prependIPHeader (pkt, MME1IP, ENB2IP, IP_TYPE_NAS);
    prependETHF4toF3 (pkt);
    meta->destination = SDN_F4_TOWARD_DATA_PORT;
    meta->action = ONVM_NF_ACTION_OUT;
    ali_debug_pprint ("hlte3 is being sent\n");
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }

  // idle to active
  if (*rte_ctrlmbuf_data (pkt) == ILTE3_MESSAGE_CODE)
  {
    ali_debug_pprint ("ilte3 message received \n");
    struct iLTE3 *i3 = (struct iLTE3 *) rte_ctrlmbuf_data (pkt);
    uint32_t tempImsi = i3->imsi;
#if TIME_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_I3]);
#endif

    struct iLTE6 *i6;

    if (sizeof (struct iLTE6) - sizeof (struct iLTE3) > 0)
    {                   // more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct iLTE6) - sizeof (struct iLTE3)));
      ali_debug_pprint2 ("increasing the size\n");
    }
    else
    {                   // the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct iLTE3) - sizeof (struct iLTE6)));
      ali_debug_pprint2 ("decreasing the size\n");
    }
    i6 = (struct iLTE6 *) rte_ctrlmbuf_data (pkt);
    i6->messageCode = ILTE6_MESSAGE_CODE;
    i6->imsi = tempImsi;
    //  l3->ip = users[tempImsi].ip;
    //snprintf (ar->autn, 256, "%s", "This is autn!");

    prependIPHeader (pkt, MME1IP, ENB1IP, IP_TYPE_NAS);
    prependETHF4toF3 (pkt);
    meta->destination = SDN_F4_TOWARD_DATA_PORT;
    meta->action = ONVM_NF_ACTION_OUT;
    ali_debug_pprint ("ilte6 is being sent\n");
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }

  // active to idle
  if (*rte_ctrlmbuf_data (pkt) == ALTE1_MESSAGE_CODE)
  {
    ali_debug_pprint ("alte1 message received \n");
    struct aLTE1 *a1 = (struct aLTE1 *) rte_ctrlmbuf_data (pkt);
    uint32_t tempImsi = a1->imsi;
#if TIME_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_A1]);
#endif

    struct aLTE2 *a2;

    if (sizeof (struct aLTE2) - sizeof (struct aLTE1) > 0)
    {                   // more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct aLTE2) - sizeof (struct aLTE1)));
      ali_debug_pprint2 ("increasing the size\n");
    }
    else
    {                   // the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct aLTE1) - sizeof (struct aLTE2)));
      ali_debug_pprint2 ("decreasing the size\n");
    }
    a2 = (struct aLTE2 *) rte_ctrlmbuf_data (pkt);
    a2->messageCode = ALTE2_MESSAGE_CODE;
    a2->imsi = tempImsi;
    //l5->indirects1dl = tempindirects1dl;
    //l3->ip = users[tempImsi].ip;
    //snprintf (ar->autn, 256, "%s", "This is autn!");

    prependIPHeader (pkt, MME1IP, SGW1IP, IP_TYPE_GCONTROL);
    //prependETHF4toF3 (pkt);
    meta->destination = LTE_SGW1_SERVICE_ID;
    meta->action = ONVM_NF_ACTION_TONF;
    ali_debug_pprint ("alte2 is being sent\n");
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }

  // detach
  if (*rte_ctrlmbuf_data (pkt) == DLTE1_MESSAGE_CODE)
  {
    ali_debug_pprint ("dlte1 message received \n");
    struct dLTE1 *d1 = (struct dLTE1 *) rte_ctrlmbuf_data (pkt);
    uint32_t tempImsi = d1->imsi;
#if TIME_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_D1]);
#endif

    struct dLTE2 *d2;

    if (sizeof (struct dLTE2) - sizeof (struct dLTE1) > 0)
    {                   // more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct dLTE2) - sizeof (struct dLTE1)));
      ali_debug_pprint2 ("increasing the size\n");
    }
    else
    {                   // the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct dLTE1) - sizeof (struct dLTE2)));
      ali_debug_pprint2 ("decreasing the size\n");
    }
    d2 = (struct dLTE2 *) rte_ctrlmbuf_data (pkt);
    d2->messageCode = DLTE2_MESSAGE_CODE;
    d2->imsi = tempImsi;
    //l5->indirects1dl = tempindirects1dl;
    //l3->ip = users[tempImsi].ip;
    //snprintf (ar->autn, 256, "%s", "This is autn!");

    prependIPHeader (pkt, MME1IP, SGW1IP, IP_TYPE_GCONTROL);
    //prependETHF4toF3 (pkt);
    meta->destination = LTE_SGW1_SERVICE_ID;
    meta->action = ONVM_NF_ACTION_TONF;
    ali_debug_pprint ("dlte2 is being sent to sgw\n");
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }

  // ilte 10
  if (*rte_ctrlmbuf_data (pkt) == ILTE10_MESSAGE_CODE)
  {
    ali_debug_pprint ("ilte10 message received \n");
    struct iLTE10 *i10 = (struct iLTE10 *) rte_ctrlmbuf_data (pkt);
    uint32_t tempImsi = i10->imsi;
#if TIME_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_I10]);
#endif

    struct iLTE11 *i11;

    if (sizeof (struct iLTE11) - sizeof (struct iLTE10) > 0)
    {                   // more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct iLTE11) - sizeof (struct iLTE10)));
      ali_debug_pprint2 ("increasing the size\n");
    }
    else
    {                   // the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct iLTE10) - sizeof (struct iLTE11)));
      ali_debug_pprint2 ("decreasing the size\n");
    }
    i11 = (struct iLTE11 *) rte_ctrlmbuf_data (pkt);
    i11->messageCode = ILTE11_MESSAGE_CODE;
    i11->imsi = tempImsi;
    //l5->indirects1dl = tempindirects1dl;
    //l3->ip = users[tempImsi].ip;
    //snprintf (ar->autn, 256, "%s", "This is autn!");

    prependIPHeader (pkt, MME1IP, SGW1IP, IP_TYPE_GCONTROL);
    //prependETHF4toF3 (pkt);
    meta->destination = LTE_SGW1_SERVICE_ID;
    meta->action = ONVM_NF_ACTION_TONF;
    ali_debug_pprint ("ilte11 is being sent to sgw\n");
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }



  if (*rte_ctrlmbuf_data (pkt) == LTE_3_ATTACH_CODE)	// it is an attach command
  {
    ali_debug_pprint ("an attach message received \n");
    struct lte3Attach *lam = (struct lte3Attach *) rte_ctrlmbuf_data (pkt);
    uint32_t tempImsi = lam->imsi;
#if TIME_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_T3]);
#endif

    if (tempImsi > USER_STATE_SIZE)
      critical_print ("large imsi! %u \n", tempImsi);

    struct lte6AuthRequest *ar;
    rte_pktmbuf_append (pkt, sizeof (struct lte6AuthRequest) - sizeof (struct lte3Attach));
    ar = (struct lte6AuthRequest *) rte_ctrlmbuf_data (pkt);
    ar->messageCode = LTE_6_AUTH_REQ_CODE;
    ar->imsi = tempImsi;
    ar->rand = 7;
    snprintf (ar->autn, 256, "%s", "This is autn!");

    prependIPHeader (pkt, MME1IP, ENB1IP, IP_TYPE_NAS);
    prependETHF4toF3 (pkt);
    meta->destination = SDN_F4_TOWARD_DATA_PORT;
    meta->action = ONVM_NF_ACTION_OUT;
    ali_debug_pprint ("auth request is being sent\n");
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }
  if (*rte_ctrlmbuf_data (pkt) == LTE_7_AUTH_RES_CODE)
  {
    ali_debug_pprint ("an auth response  message received \n");
    struct lte7AuthResponse *lar = (struct lte7AuthResponse *) rte_ctrlmbuf_data (pkt);
    uint32_t tempImsi = lar->imsi;
#if TIME_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_T7]);
#endif

    if (tempImsi > USER_STATE_SIZE)
      critical_print ("large imsi! %u \n", tempImsi);

    struct lte8SecMod *lsm;
    if (sizeof (struct lte8SecMod) - sizeof (struct lte7AuthResponse) > 0)
    {			// more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct lte8SecMod) - sizeof (struct lte7AuthResponse)));
      ali_debug_pprint ("increasing the size\n");
    }
    else
    {			// the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct lte7AuthResponse) - sizeof (struct lte8SecMod)));
      ali_debug_pprint ("decreasing the size\n");
    }
    lsm = (struct lte8SecMod *) rte_ctrlmbuf_data (pkt);
    lsm->messageCode = LTE_8_SEC_MOD_CODE;
    lsm->imsi = tempImsi;
    //snprintf ( ar->autn, 256, "%s", "This is autn!" );

    prependIPHeader (pkt, MME1IP, ENB1IP, IP_TYPE_NAS);
    prependETHF4toF3 (pkt);
    meta->destination = SDN_F4_TOWARD_DATA_PORT;
    meta->action = ONVM_NF_ACTION_OUT;
    ali_debug_pprint ("security mode command is being sent\n");
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }
  if (*rte_ctrlmbuf_data (pkt) == LTE_9_KEY_GEN_CODE)
  {
    ali_debug_pprint ("a key gen complete  message received \n");
    struct lte9KeyGen *lkg = (struct lte9KeyGen *) rte_ctrlmbuf_data (pkt);
    uint32_t tempImsi = lkg->imsi;
#if TIME_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_T9]);
#endif

    struct lte12EpsReq *ler;
    if (tempImsi > USER_STATE_SIZE)
      critical_print ("large imsi! %u \n", tempImsi);

    if (sizeof (struct lte12EpsReq) - sizeof (struct lte9KeyGen) > 0)
    {			// more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct lte12EpsReq) - sizeof (struct lte9KeyGen)));
      ali_debug_pprint ("increasing the size\n");
    }
    else
    {			// the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct lte9KeyGen) - sizeof (struct lte12EpsReq)));
      ali_debug_pprint ("decreasing the size\n");
    }
    ler = (struct lte12EpsReq *) rte_ctrlmbuf_data (pkt);
    ler->messageCode = LTE_12_EPS_REQ_CODE;
    ler->imsi = tempImsi;
    //snprintf ( ar->autn, 256, "%s", "This is autn!" );

    prependIPHeader (pkt, MME1IP, SGW1IP, IP_TYPE_GCONTROL);
    //prependETHF4toF3(pkt);
    meta->destination = LTE_SGW1_SERVICE_ID;
    meta->action = ONVM_NF_ACTION_TONF;
    ali_debug_pprint ("Req for eps session command is being sent\n");
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }
  //LTE_25_CONTEXT_RES_CODE,LTE_26_ATTACH_COMPLETE_CODE,LTE_27_BEARER_MOD_CODE,LTE_28_MOD_RES_CODE
  //lte25ContextRes,lte26AttachComplete,lte27BrearerMod,lte28ModRes,,LTE_27_BEARER_MOD_CODE,LTE_28_MOD_RES_CODE
  if (*rte_ctrlmbuf_data (pkt) == LTE_26_ATTACH_COMPLETE_CODE)
  {
    ali_debug_pprint ("26 received \n");
#if TIME_LOGGING == ACTIVATED
    struct lte25ContextRes *lcr = (struct lte25ContextRes *) rte_ctrlmbuf_data (pkt);
    uint32_t tempImsi = lcr->imsi;
    clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_T26]);
#endif

    /*struct lte12EpsReq *ler;
      if (sizeof (struct lte12EpsReq) - sizeof (struct lte9KeyGen) > 0)
      {                   // more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct lte12EpsReq) - sizeof (struct lte9KeyGen)));
      ali_debug_pprint ("increasing the size\n");
      }
      else
      {                   // the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct lte9KeyGen) - sizeof (struct lte12EpsReq)));
      ali_debug_pprint ("decreasing the size\n");
      }
      ler = (struct lte12EpsReq *) rte_ctrlmbuf_data (pkt);
      ler->messageCode = LTE_12_EPS_REQ_CODE;
      ler->imsi = tempImsi;
    //snprintf ( ar->autn, 256, "%s", "This is autn!" );

    prependIPHeader (pkt, MME1IP, SGW1IP, IP_TYPE_GCONTROL);
    //prependETHF4toF3(pkt);*/
    //meta->destination = LTE_SGW1_SERVICE_ID;
    meta->action = ONVM_NF_ACTION_DROP;
    //ali_debug_pprint ("Req for eps session command is being sent\n");
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }
  if (*rte_ctrlmbuf_data (pkt) == LTE_25_CONTEXT_RES_CODE)
  {
    ali_debug_pprint ("25  message received \n");
    struct lte25ContextRes *lcr = (struct lte25ContextRes *) rte_ctrlmbuf_data (pkt);
    uint32_t tempImsi = lcr->imsi;
#if TIME_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_T25]);
#endif

    if (tempImsi > USER_STATE_SIZE)
      critical_print ("large imsi! %u \n", tempImsi);

    uint32_t temps1dl = lcr->s1dl;
    struct lte27BrearerMod *lbm;
    if (sizeof (struct lte27BrearerMod) - sizeof (struct lte25ContextRes) > 0)
    {                   // more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct lte27BrearerMod) - sizeof (struct lte25ContextRes)));
      ali_debug_pprint ("increasing the size\n");
    }
    else
    {                   // the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct lte25ContextRes) - sizeof (struct lte27BrearerMod)));
      ali_debug_pprint ("decreasing the size\n");
    }
    lbm = (struct lte27BrearerMod *) rte_ctrlmbuf_data (pkt);
    lbm->messageCode = LTE_27_BEARER_MOD_CODE;
    lbm->imsi = tempImsi;
    lbm->s1dl = temps1dl;
    //snprintf ( ar->autn, 256, "%s", "This is autn!" );

    prependIPHeader (pkt, MME1IP, SGW1IP, IP_TYPE_GCONTROL);
    //prependETHF4toF3(pkt);
    meta->destination = LTE_SGW1_SERVICE_ID;
    meta->action = ONVM_NF_ACTION_TONF;
    ali_debug_pprint ("27 is being sent\n");
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }
  //	}
  //printf("next proto id is: %i\n", iph->next_proto_id);
  //	if (iph->next_proto_id == IP_TYPE_GCONTROL)
  //	{
  //		ali_debug_pprint ("control packet received\n");
  // remove the ip header
  //		rte_pktmbuf_adj (pkt, 20);

  // ilte 16
  if (*rte_ctrlmbuf_data (pkt) == ILTE16_MESSAGE_CODE)
  {
    ali_debug_pprint ("ilte16 message received \n");
    struct iLTE16 *i16 = (struct iLTE16 *) rte_ctrlmbuf_data (pkt);
    uint32_t tempImsi = i16->imsi;
#if TIME_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_I16]);
#endif

    struct iLTE18 *i18;

    if (sizeof (struct iLTE18) - sizeof (struct iLTE16) > 0)
    {                   // more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct iLTE18) - sizeof (struct iLTE16)));
      ali_debug_pprint2 ("increasing the size\n");
    }
    else
    {                   // the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct iLTE16) - sizeof (struct iLTE18)));
      ali_debug_pprint2 ("decreasing the size\n");
    }
    i18 = (struct iLTE18 *) rte_ctrlmbuf_data (pkt);
    i18->messageCode = ILTE18_MESSAGE_CODE;
    i18->imsi = tempImsi;
    //l5->indirects1dl = tempindirects1dl;
    //l3->ip = users[tempImsi].ip;
    //snprintf (ar->autn, 256, "%s", "This is autn!");

    prependIPHeader (pkt, MME1IP, ENB1IP, IP_TYPE_GCONTROL);
    prependETHF4toF3 (pkt);
    meta->destination = SDN_F4_TOWARD_DATA_PORT;
    meta->action = ONVM_NF_ACTION_OUT;
    ali_debug_pprint ("ILTE 18 IS BEING SENT\n");
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }

  if (*rte_ctrlmbuf_data (pkt) == ALTE3_MESSAGE_CODE)
  {
    ali_debug_pprint ("alte 3 message received \n");
    struct aLTE3 *a3 = (struct aLTE3 *) rte_ctrlmbuf_data (pkt);
    uint32_t tempImsi = a3->imsi;
#if TIME_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_A3]);
#endif

    //uint32_t temps1dl = l4->s1dl;
    //users[tempImsi].targets1dl = temps1dl;
    //uint32_t tempindirects1dl = l4->indirects1dl;
    struct aLTE4 *a4;

    if (sizeof (struct aLTE4) - sizeof (struct aLTE3) > 0)
    {                   // more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct aLTE4) - sizeof (struct aLTE3)));
      ali_debug_pprint2 ("increasing the size\n");
    }
    else
    {                   // the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct aLTE3) - sizeof (struct aLTE4)));
      ali_debug_pprint2 ("decreasing the size\n");
    }

    a4 = (struct aLTE4 *) rte_ctrlmbuf_data (pkt);
    a4->messageCode = ALTE4_MESSAGE_CODE;
    a4->imsi = tempImsi;
    //l13->targets1dl = users[tempImsi].targets1dl;
    //l5->indirects1dl = tempindirects1dl;
    //l3->ip = users[tempImsi].ip;
    //snprintf (ar->autn, 256, "%s", "This is autn!");

    prependIPHeader (pkt, MME1IP, ENB1IP, IP_TYPE_GCONTROL);
    prependETHF4toF3 (pkt);
    meta->destination = SDN_F4_TOWARD_DATA_PORT;
    meta->action = ONVM_NF_ACTION_OUT;
    ali_debug_pprint ("alte 4 is being sent\n");
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }
  // a6
  if (*rte_ctrlmbuf_data (pkt) == ALTE6_MESSAGE_CODE)
  {
    ali_debug_pprint ("alte 6 message received \n");
    struct aLTE6 *a6 = (struct aLTE6 *) rte_ctrlmbuf_data (pkt);
    uint32_t tempImsi = a6->imsi;
#if TIME_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_A6]);
#endif

    //uint32_t temps1dl = l4->s1dl;
    //users[tempImsi].targets1dl = temps1dl;
    //uint32_t tempindirects1dl = l4->indirects1dl;
    struct aLTE7 *a7;

    if (sizeof (struct aLTE7) - sizeof (struct aLTE6) > 0)
    {                   // more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct aLTE7) - sizeof (struct aLTE6)));
      ali_debug_pprint2 ("increasing the size\n");
    }
    else
    {                   // the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct aLTE6) - sizeof (struct aLTE7)));
      ali_debug_pprint2 ("decreasing the size\n");
    }

    a7 = (struct aLTE7 *) rte_ctrlmbuf_data (pkt);
    a7->messageCode = ALTE7_MESSAGE_CODE;
    a7->imsi = tempImsi;
    //l13->targets1dl = users[tempImsi].targets1dl;
    //l5->indirects1dl = tempindirects1dl;
    //l3->ip = users[tempImsi].ip;
    //snprintf (ar->autn, 256, "%s", "This is autn!");

    prependIPHeader (pkt, MME1IP, ENB1IP, IP_TYPE_GCONTROL);
    prependETHF4toF3 (pkt);
    meta->destination = SDN_F4_TOWARD_DATA_PORT;
    meta->action = ONVM_NF_ACTION_OUT;
    ali_debug_pprint ("alte 7 is being sent!\n");
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }
  // d11
  if (*rte_ctrlmbuf_data (pkt) == DLTE11_MESSAGE_CODE)
  {
    ali_debug_pprint ("dlte 11 message received \n");
    struct dLTE11 *d11 = (struct dLTE11 *) rte_ctrlmbuf_data (pkt);
    uint32_t tempImsi = d11->imsi;
#if TIME_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_D11]);
#endif

    //uint32_t temps1dl = l4->s1dl;
    //users[tempImsi].targets1dl = temps1dl;
    //uint32_t tempindirects1dl = l4->indirects1dl;
    struct dLTE12 *d12;

    if (sizeof (struct dLTE12) - sizeof (struct dLTE11) > 0)
    {                   // more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct dLTE12) - sizeof (struct dLTE11)));
      ali_debug_pprint2 ("increasing the size\n");
    }
    else
    {                   // the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct dLTE11) - sizeof (struct dLTE12)));
      ali_debug_pprint2 ("decreasing the size\n");
    }

    d12 = (struct dLTE12 *) rte_ctrlmbuf_data (pkt);
    d12->messageCode = DLTE12_MESSAGE_CODE;
    d12->imsi = tempImsi;
    //l13->targets1dl = users[tempImsi].targets1dl;
    //l5->indirects1dl = tempindirects1dl;
    //l3->ip = users[tempImsi].ip;
    //snprintf (ar->autn, 256, "%s", "This is autn!");

    prependIPHeader (pkt, MME1IP, ENB1IP, IP_TYPE_GCONTROL);
    prependETHF4toF3 (pkt);
    meta->destination = SDN_F4_TOWARD_DATA_PORT;
    meta->action = ONVM_NF_ACTION_OUT;
    ali_debug_pprint ("dlte 12 is being sent!\n");
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }


  // D7
  if (*rte_ctrlmbuf_data (pkt) == DLTE7_MESSAGE_CODE)        // it is an attach command
  {
    ali_debug_pprint ("dlte 7 message received \n");
    struct dLTE7 *d7 = (struct dLTE7 *) rte_ctrlmbuf_data (pkt);
    uint32_t tempImsi = d7->imsi;
#if TIME_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_D7]);
#endif

    //uint32_t temps1dl = l4->s1dl;
    //users[tempImsi].targets1dl = temps1dl;
    //uint32_t tempindirects1dl = l4->indirects1dl;
    struct dLTE8 *d8; //detach response

    if (sizeof (struct dLTE8) - sizeof (struct dLTE7) > 0)
    {                   // more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct dLTE8) - sizeof (struct dLTE7)));
      ali_debug_pprint2 ("increasing the size\n");
    }
    else
    {                   // the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct dLTE7) - sizeof (struct dLTE8)));
      ali_debug_pprint2 ("decreasing the size\n");
    }

    d8 = (struct dLTE8 *) rte_ctrlmbuf_data (pkt);
    d8->messageCode = DLTE8_MESSAGE_CODE;
    d8->imsi = tempImsi;
    //l13->targets1dl = users[tempImsi].targets1dl;
    //l5->indirects1dl = tempindirects1dl;
    //l3->ip = users[tempImsi].ip;
    //snprintf (ar->autn, 256, "%s", "This is autn!");

    prependIPHeader (pkt, MME1IP, ENB1IP, IP_TYPE_GCONTROL);
    prependETHF4toF3 (pkt);
    meta->destination = SDN_F4_TOWARD_DATA_PORT;
    meta->action = ONVM_NF_ACTION_OUT;
    ali_debug_pprint ("dlte 8 is being sent\n");
    //now we need to send message 9
    struct rte_mempool *pktmbuf_pool;
    struct rte_mbuf *newpkt;
    pktmbuf_pool = rte_mempool_lookup (PKTMBUF_POOL_NAME);
    if (pktmbuf_pool == NULL)
    {
      rte_exit (EXIT_FAILURE, "Cannot find mbuf pool!\n");
    }
    ali_debug_pprint ("Start sending packet D9\n");
    struct onvm_pkt_meta *pmeta;
    newpkt = rte_pktmbuf_alloc (pktmbuf_pool);
    if (newpkt == NULL) {
      printf ("could not allocate pkt!\n");
    }
    struct dLTE9 *d9;
    d9 = (struct dLTE9 *) rte_pktmbuf_prepend (newpkt, sizeof (struct dLTE9));
    d9->messageCode = DLTE9_MESSAGE_CODE;
    d9->imsi = tempImsi;
    //ler->s1u1 = temps1ul;
    //snprintf ( ar->autn, 256, "%s", "This is autn!" );
    prependIPHeader (newpkt, MME1IP, ENB1IP, IP_TYPE_NAS);
    prependETHF4toF3(newpkt);
    //fill it here    
    pmeta = onvm_get_pkt_meta (newpkt);
    pmeta->destination = SDN_F4_TOWARD_DATA_PORT;
    pmeta->action = ONVM_NF_ACTION_OUT;
    onvm_nflib_return_pkt (newpkt);
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }

  if (*rte_ctrlmbuf_data (pkt) == HLTE6_MESSAGE_CODE)
  {
    //BUG: 21 IS SEND FIRST AND THEN 20 IS SENT, BECAUSE OF IT, THE CODE IN ENB IS MODIFIED TOO
    ali_debug_pprint ("HLTE6 received \n");
    struct hLTE6 *l6 = (struct hLTE6 *) rte_ctrlmbuf_data (pkt);
    uint32_t tempImsi = l6->imsi;
#if TIME_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_H6]);
#endif

    //uint32_t tempip = ler19->ip;
    //users[tempImsi].ip = tempip;
    //ali_debug_print2 ("tempip %lu\n", (unsigned long) tempip);
    uint32_t temps1ul = l6->s1ul;
    struct hLTE7 *l7;
    if (sizeof (struct hLTE7) - sizeof (struct hLTE6) > 0)
    {			// more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct hLTE7) - sizeof (struct hLTE6)));
      ali_debug_pprint ("increasing the size\n");
    }
    else
    {			// the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct hLTE6) - sizeof (struct hLTE7)));
      ali_debug_pprint ("decreasing the size\n");
    }
    l7 = (struct hLTE7 *) rte_ctrlmbuf_data (pkt);
    //LTE_21_ERAB_REQ_CODE,lte19EpsRes,lte20AttachAccept,lte21ErabReq
    l7->messageCode = HLTE7_MESSAGE_CODE;
    l7->imsi = tempImsi;
    l7->s1ul = temps1ul;
    //laa->s1ul = temps1ul;
    //snprintf ( ar->autn, 256, "%s", "This is autn!" );

    prependIPHeader (pkt, MME1IP, ENB1IP, IP_TYPE_NAS);
    prependETHF4toF3(pkt);
    meta->destination = SDN_F4_TOWARD_DATA_PORT;
    meta->action = ONVM_NF_ACTION_OUT;
    ali_debug_pprint ("hlte7 sent to enb1\n");
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }

  if (*rte_ctrlmbuf_data (pkt) == LTE_19_EPS_RES_CODE)
  {
    //BUG: 21 IS SEND FIRST AND THEN 20 IS SENT, BECAUSE OF IT, THE CODE IN ENB IS MODIFIED TOO
    ali_debug_pprint ("a lte 19 received \n");
    struct lte19EpsRes *ler19 = (struct lte19EpsRes *) rte_ctrlmbuf_data (pkt);
    uint32_t tempImsi = ler19->imsi;
#if TIME_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_T19]);
#endif

    uint32_t tempip = ler19->ip;
    if (tempImsi > USER_STATE_SIZE)
      critical_print ("large imsi! %u \n", tempImsi);
    if (tempImsi <USER_STATE_SIZE){
      //		                  users[tempImsi].targets1dl = temps1dl;
      //users[tempImsi].ip = tempip;
      struct lteMMEUserState* user = NULL;
      user = retrievestate(tempImsi);
      if (user == NULL) {
	user = addNewKey (tempImsi);
      }
      if (user == NULL) {
	printf ("we failed in retrieving a key or making a new key!\n");
	meta->action = ONVM_NF_ACTION_DROP;
	return 0;

      } else {
	user->ip = tempip;
      }


    } else {
      printf ("problem4!!! tempImsi is out of range! %u \n", tempImsi);
    }
    ali_debug_print2 ("tempip %lu\n", (unsigned long) tempip);
    uint32_t temps1ul = ler19->s1ul;
    struct lte20AttachAccept *laa;
    if (sizeof (struct lte20AttachAccept) - sizeof (struct lte19EpsRes) > 0)
    {			// more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct lte20AttachAccept) - sizeof (struct lte19EpsRes)));
      ali_debug_pprint ("increasing the size\n");
    }
    else
    {			// the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct lte19EpsRes) - sizeof (struct lte20AttachAccept)));
      ali_debug_pprint ("decreasing the size\n");
    }
    laa = (struct lte20AttachAccept *) rte_ctrlmbuf_data (pkt);
    //LTE_21_ERAB_REQ_CODE,lte19EpsRes,lte20AttachAccept,lte21ErabReq
    laa->messageCode = LTE_20_ATCH_ACPT_CODE;
    laa->imsi = tempImsi;
    laa->ip = tempip;
    //laa->s1ul = temps1ul;
    //snprintf ( ar->autn, 256, "%s", "This is autn!" );

    prependIPHeader (pkt, MME1IP, ENB1IP, IP_TYPE_NAS);
    prependETHF4toF3(pkt);
    meta->destination = SDN_F4_TOWARD_DATA_PORT;
    meta->action = ONVM_NF_ACTION_OUT;
    ali_debug_pprint ("attach accept sent\n");
    //now we need to send message 21
    struct rte_mempool *pktmbuf_pool;
    struct rte_mbuf *newpkt;
    pktmbuf_pool = rte_mempool_lookup (PKTMBUF_POOL_NAME);
    if (pktmbuf_pool == NULL)
    {
      rte_exit (EXIT_FAILURE, "Cannot find mbuf pool!\n");
    }
    ali_debug_pprint ("Start sending packet 21\n");
    struct onvm_pkt_meta *pmeta;
    newpkt = rte_pktmbuf_alloc (pktmbuf_pool);
    struct lte21ErabReq *ler;
    ler = (struct lte21ErabReq *) rte_pktmbuf_prepend (newpkt, sizeof (struct lte21ErabReq));
    ler->messageCode = LTE_21_ERAB_REQ_CODE;
    ler->imsi = tempImsi;
    ler->s1u1 = temps1ul;
    //snprintf ( ar->autn, 256, "%s", "This is autn!" );
    prependIPHeader (newpkt, MME1IP, ENB1IP, IP_TYPE_NAS);
    prependETHF4toF3(newpkt);
    //fill it here    
    pmeta = onvm_get_pkt_meta (newpkt);
    pmeta->destination = SDN_F4_TOWARD_DATA_PORT;
    pmeta->action = ONVM_NF_ACTION_OUT;
    onvm_nflib_return_pkt (newpkt);
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }

  if (*rte_ctrlmbuf_data (pkt) == LTE_28_MOD_RES_CODE)
  {
    ali_debug_pprint ("t28 received \n");
    struct lte28ModRes *lmr = (struct lte28ModRes *) rte_ctrlmbuf_data (pkt);
    uint32_t tempImsi = lmr->imsi;
#if TIME_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &tl[tempImsi][TL_T28]);
#endif

    struct tLTE29 *t29;
    if (sizeof (struct tLTE29) - sizeof (struct lte28ModRes) > 0)
    {                   // more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct tLTE29) - sizeof (struct lte28ModRes)));
      ali_debug_pprint ("increasing the size\n");
    }
    else
    {                   // the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct lte28ModRes) - sizeof (struct tLTE29)));
      ali_debug_pprint ("decreasing the size\n");
    }
    t29 = (struct tLTE29 *) rte_ctrlmbuf_data (pkt);
    t29->messageCode = TLTE29_MESSAGE_CODE;
    t29->imsi = tempImsi;
    //snprintf ( ar->autn, 256, "%s", "This is autn!" );

    prependIPHeader (pkt, MME1IP, ENB1IP, IP_TYPE_NAS);
    prependETHF4toF3(pkt);
    meta->destination = SDN_F4_TOWARD_DATA_PORT;
    meta->action = ONVM_NF_ACTION_OUT;
    ali_debug_pprint ("t29 is being sent\n");
#if UTILIZATION_LOGGING == ACTIVATED
    clock_gettime(CLOCK_REALTIME, &lastExitTime);
    totalActiveTimeInLastPeriod += returnNanoDifference (currentTime, lastExitTime);
#endif

    return 0;
  }
  //	}
  // unhandled pacekt
  printf ("We shouldn't get here! unhandled packet \n");
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
#if UTILIZATION_LOGGING == ACTIVATED
  clock_gettime(CLOCK_REALTIME, &lastExitTime);
  int i = 0;
  for ( i = 0 ; i < MAXIMUM_RUN_TIME_IN_SECONDS; i++) {
    utilization [i] = -1;
  }
#endif
  ali_debug_pprint("before setting hash parametres\n");
  struct rte_hash_parameters encap_hash_params = {
    .name = "mmeHash",
    .entries = USER_STATE_SIZE,
    .key_len = sizeof(uint32_t),
    .hash_func = DEFAULT_HASH_FUNC,
    .hash_func_init_val = 0,
    .socket_id = rte_socket_id(),
  };
  ali_debug_pprint("after setting hash parameteres, before creating hash\n");
  users_hash = rte_hash_create(&encap_hash_params);
  if (users_hash == NULL) {
    critical_pprint("unable to make the hash!!\n");
  }
  ali_debug_pprint("hash created successfully\n");

  onvm_nflib_run (nf_info, &packet_handler);
#if TIME_LOGGING == ACTIVATED
  writeTimeLogToFile ("f4mme.txt", tl);
#endif
#if UTILIZATION_LOGGING == ACTIVATED
  recordUtilizationLog ("ULogf4mme.txt", utilization);
#endif
  printf ("If we reach here, program is ending");
  return 0;
}
