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
 * speed_tester.c - create pkts and loop through NFs.
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
#include <sys/time.h>
#include <math.h>
#include <time.h>

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_mempool.h>
#include <rte_cycles.h>


#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "lteCore.h"

#define NF_TAG "speed"

#define NUM_PKTS NUMBER_OF_USERS
//#define PKTMBUF_POOL_NAME "MProc_pktmbuf_pool"
#define NORMAL_WITHOUT_WAIT 0
#define NORMAL_WITH_WAIT 1
#define WAIT_BURST 2
#define NORMAL_WAIT 1000
#define WB_WAIT 1000000
#define WB_BURST_SIZE 20
#define SCENARIO_PATTERN NORMAL_WITHOUT_WAIT
#define SEQUENTIAL_ATTACH ACTIVATED
#define SEQUENTIAL_HANDOVER ACTIVATED
#define SEQUENTIAL_IDLE_TO_ACTIVE ACTIVATED
#define SEQUENTIAL_ACTIVE_TO_IDLE ACTIVATED
#define SEQUENTIAL_DETACH ACTIVATED



//#define WAIT_ATTACH_HANDOVER 1000000
/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

/* number of package between each print */
static uint32_t print_delay = 10000000;
static uint16_t destination;
static struct timespec startTimes[USER_STATE_SIZE];
static struct timespec handoverStartTimes[USER_STATE_SIZE];
//static struct timespec activeToIdleStartTimes[USER_STATE_SIZE];
//static struct timespec idleToActiveStartTimes[USER_STATE_SIZE];
//static struct timespec detachCommandStartTimes[USER_STATE_SIZE];
static struct scenarioGenUserState usersState[NUMBER_OF_USERS];
//(struct rte_mempool *, void *, void *, unsigned int)
void debugPrintMbuf (struct rte_mempool *, void *, void *, unsigned int);
static double dynamic_scenario_rate_multiplier = 0;

//static uint32_t foo [20000];
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
  static uint64_t last_cycles;
  static uint64_t cur_pkts = 0;
  static uint64_t last_pkts = 0;
  const char clr[] = { 27, '[', '2', 'J', '\0' };
  const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };
  (void) pkt;

  uint64_t cur_cycles = rte_get_tsc_cycles ();
  cur_pkts += print_delay;

  /* Clear screen and move to top left */
  printf ("%s%s", clr, topLeft);

  printf ("Total packets: %9" PRIu64 " \n", cur_pkts);
  printf ("TX pkts per second: %9" PRIu64 " \n", (cur_pkts - last_pkts) * rte_get_timer_hz () / (cur_cycles - last_cycles));
  printf ("Packets per group: %d\n", NUM_PKTS);

  last_pkts = cur_pkts;
  last_cycles = cur_cycles;

  printf ("\n\n");
}


  static void
user_stats_display ( int numOfUsersInDisc, int numOfUsersInConn, int numOfUsersInIdle, int numberOfHandovers, int while_counter)
{
  const char clr[] = { 27, '[', '2', 'J', '\0' };
  const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };
  
  printf ("%s%s", clr, topLeft);
  printf("No of users in disc %d, in conn %d, in idle %d and No of Handovers %d\n", numOfUsersInDisc, numOfUsersInConn, numOfUsersInIdle, numberOfHandovers);
  printf("percentage of final rate is %f \n", 1.0 * while_counter / SCENARIO_RATE_STEPS);
  printf ("\n\n");
}




  static int
packet_handler (struct rte_mbuf *pkt, struct onvm_pkt_meta *meta, __attribute__((unused)) struct onvm_nf_info *nf_info)
{
  static uint32_t counter = 0;
  if (counter++ == print_delay && SHOW_PACKET_STATS != DISABLED)
  {
    do_stats_display (pkt);
    counter = 0;
  }

  if (pkt->port == 3)
  {
    /* one of our fake pkts to forward */
    meta->destination = destination;
    meta->action = ONVM_NF_ACTION_TONF;
  }
  else
  {
    /* Drop real incoming packets */
    ali_debug_pprint ("a respond received from replier");
    meta->action = ONVM_NF_ACTION_DROP;
  }
  return 0;
}

//(struct rte_mempool *, void *, void *, unsigned int)
void debugPrintMbuf (__attribute__((unused)) struct rte_mempool * pool, __attribute__((unused)) void * opaq, void * invPkt, __attribute__((unused)) unsigned int index) {
  static uint32_t mbufCounter = 0;
  mbufCounter++;
  struct rte_mbuf* mbuf = (struct rte_mbuf*) invPkt;
  //printf ("packet len is %u\n", rte_pktmbuf_pkt_len (mbuf));
  printf ("hello! we are in debugPrintMbuf\n");
  struct onvm_pkt_meta *pmeta;
  pmeta = onvm_get_pkt_meta ( mbuf);
  printf ("mbuf no is %u destination is %u and action is %u\n", mbufCounter, pmeta->destination, pmeta->action );
}

  static void
scenario_send_packet (uint32_t initialUserID, uint32_t noOfUsers, uint32_t packetType, struct timespec st[])
{
  struct rte_mempool *pktmbuf_pool;
  struct rte_mbuf *pkts[noOfUsers];
  uint32_t i;

  pktmbuf_pool = rte_mempool_lookup (PKTMBUF_POOL_NAME);
  if (pktmbuf_pool == NULL)
  {
    ali_debug_pprint("cannot find pooooool!!!!exit!\n");
    rte_exit (EXIT_FAILURE, "Cannot find mbuf pool!\n");
  }
  ali_debug_print ("Creating %d packets to send to %d from type %ld with initial user id of %u\n", noOfUsers, destination, (unsigned long) packetType, initialUserID);
  struct timespec tsp;
  clock_gettime (CLOCK_REALTIME, &tsp);
  for (i = initialUserID; i < noOfUsers + initialUserID; i++)
  {
    int userCounter = i - initialUserID;
    ali_debug_print ("Start sending packet: %d\n", i);
    struct onvm_pkt_meta *pmeta;
    ali_debug_pprint2("before alloc of po0ool \n");
    //Follwoing line was the original version
    //pkts[userCounter] = rte_pktmbuf_alloc (pktmbuf_pool);
    //changed to following for debugging purposes, ali change it backe! TODO
    pkts[userCounter] = rte_pktmbuf_alloc (rte_mempool_lookup (PKTMBUF_POOL_NAME));
    if (pkts[userCounter] == NULL) {
      printf ("not able to allocate memory!\n");

      /*
      uint32_t rte_mempool_obj_iter ( struct rte_mempool *  mp,
      rte_mempool_obj_cb_t *  obj_cb,
      void *  obj_cb_arg 
      )	
      // add code to print what's going on in the memory!
      TODO: This memory printing is just for debugging purposes!
      */
      uint32_t returnCode = rte_mempool_obj_iter (pktmbuf_pool, debugPrintMbuf, NULL);
      rte_exit(EXIT_FAILURE, "cannot allocate memory!\n");
      printf ("retrun code is %u\n", returnCode);
      unsigned int inuse = rte_mempool_in_use_count (pktmbuf_pool);
            unsigned int available = rte_mempool_avail_count(pktmbuf_pool);
	          printf ("in use is %u and avail is %u \n", inuse, available);
      return;
    }
    ali_debug_pprint2("after alloc of pool \n");
    struct scenarioMessage *sm;
    ali_debug_pprint2("before first access to pkt\n");
    sm = (struct scenarioMessage *) rte_pktmbuf_prepend (pkts[userCounter], sizeof (struct scenarioMessage));
    ali_debug_pprint2("after first access to pkt\n");
    sm->command = packetType;
    sm->userID = i;
    pmeta = onvm_get_pkt_meta (pkts[userCounter]);
    pmeta->destination = LTE_ENB1_SERVICE_ID;
    pmeta->action = ONVM_NF_ACTION_TONF;
    pkts[userCounter]->port = COMMAND_MESSAGE_PORT;
    pkts[userCounter]->hash.rss = i;
    onvm_nflib_return_pkt (nf_info,pkts[userCounter]);
    clock_gettime (CLOCK_REALTIME, &st[userCounter]);
    if (SCENARIO_PATTERN == WAIT_BURST)
    {
      if (userCounter % WB_BURST_SIZE == 0)
      {
	struct timespec sleepStartTime;
	struct timespec sleepDuringTime;
	clock_gettime (CLOCK_REALTIME, &sleepStartTime);
	int w = 0;
	for (w = 0; w < 1000000; w++)
	{
	  clock_gettime (CLOCK_REALTIME, &sleepDuringTime);
	  if (sleepDuringTime.tv_nsec - sleepStartTime.tv_nsec > WB_WAIT)
	  {
	    break;
	  }
	}
      }
    }
    if (SCENARIO_PATTERN == NORMAL_WITHOUT_WAIT)
    {
    }
    if (SCENARIO_PATTERN == NORMAL_WAIT)
    {
      struct timespec sleepStartTime;
      struct timespec sleepDuringTime;
      clock_gettime (CLOCK_REALTIME, &sleepStartTime);
      int w = 0;
      for (w = 0; w < 100000; w++)
      {
	clock_gettime (CLOCK_REALTIME, &sleepDuringTime);
	if (sleepDuringTime.tv_nsec - sleepStartTime.tv_nsec > NORMAL_WITH_WAIT)
	{
	  break;
	}
      }
    }
  }
  ali_debug_pprint2("before end of function\n");
}




  int
main (int argc, char *argv[])
{
  int arg_offset;
  //printf ("Ali don't forget you have added random cores to ali file!!!!\n");
  const char *progname = argv[0];
  printf ("before init\n");
  if ((arg_offset = onvm_nflib_init (argc, argv, NF_TAG, &nf_info)) < 0)
    return -1;
  printf ("after init\n");
  argc -= arg_offset;
  argv += arg_offset;

  destination = nf_info->service_id;
  printf ("before parse\n");
  if (parse_app_args (argc, argv, progname) < 0)
    rte_exit (EXIT_FAILURE, "Invalid command-line arguments\n");
  printf ("after parse\n");
  /*
     struct timespec sleepStartTime;
     struct timespec sleepDuringTime;
     clock_gettime (CLOCK_REALTIME, &sleepStartTime);
     int w = 0;
     int roundCounter = 0;
     for (roundCounter = 0; roundCounter < NUMBER_OF_ROUNDS; roundCounter++) {
     int initialUserID = roundCounter * NUMBER_OF_USERS_PER_ROUND;
     if (SEQUENTIAL_ATTACH == ACTIVATED) {
     ali_debug_pprint ("Ready to send attach request\n");
  //HAVE SEND PACKET FUNCTION HERE
  scenario_send_packet (initialUserID, NUMBER_OF_USERS_PER_ROUND, NEW_USER_COMMAND, startTimes);
  ali_debug_pprint("after sending attach requests\n");
  //wait for a period after sending attach requests
  for (w = 0; w < MAXIMUM_WAIT_BETWEEN_STEPS; w++)
  {
  clock_gettime (CLOCK_REALTIME, &sleepDuringTime);
  if (sleepDuringTime.tv_nsec - sleepStartTime.tv_nsec > WAIT_ATTACH_HANDOVER)
  {
  //printf ("larger %d\n",w);
  break;
  }
  }
  }

  if (SEQUENTIAL_HANDOVER == ACTIVATED) {
  ali_debug_pprint("send handover command\n");
  //sedning handover command
  scenario_send_packet(initialUserID, NUMBER_OF_USERS_PER_ROUND, HANDOVER_COMMAND, handoverStartTimes);
  clock_gettime (CLOCK_REALTIME, &sleepStartTime);
  for (w = 0; w < MAXIMUM_WAIT_BETWEEN_STEPS; w++)
  {

  clock_gettime (CLOCK_REALTIME, &sleepDuringTime);
  if (sleepDuringTime.tv_nsec - sleepStartTime.tv_nsec > WAIT_HANDOVER_ACTIVE_TO_IDLE)
  {
  //printf ("larger %d\n",w);
  break;
  }
  }
  }

  if (SEQUENTIAL_ACTIVE_TO_IDLE == ACTIVATED) {
  ali_debug_pprint("sending active to idle command\n");
  scenario_send_packet(initialUserID, NUMBER_OF_USERS_PER_ROUND, ACTIVE_TO_IDLE_COMMAND, activeToIdleStartTimes);
  clock_gettime (CLOCK_REALTIME, &sleepStartTime);
  for (w = 0; w < MAXIMUM_WAIT_BETWEEN_STEPS; w++)
  {

  clock_gettime (CLOCK_REALTIME, &sleepDuringTime);
  if (sleepDuringTime.tv_nsec - sleepStartTime.tv_nsec > WAIT_ACTIVE_TO_IDLE_IDLE_TO_ACTIVE)
  {
  //printf ("larger %d\n",w);
  break;
  }
  }
  }

  if (SEQUENTIAL_IDLE_TO_ACTIVE == ACTIVATED) {
  ali_debug_pprint("sending idle to active command\n");
  scenario_send_packet(initialUserID, NUMBER_OF_USERS_PER_ROUND, IDLE_TO_ACTIVE_COMMAND, idleToActiveStartTimes);
  clock_gettime (CLOCK_REALTIME, &sleepStartTime);
  for (w = 0; w < MAXIMUM_WAIT_BETWEEN_STEPS; w++)
  {

  clock_gettime (CLOCK_REALTIME, &sleepDuringTime);
  if (sleepDuringTime.tv_nsec - sleepStartTime.tv_nsec > WAIT_IDLE_TO_ACTIVE_TO_DETACH)
  {
  //printf ("larger %d\n",w);
  break;
  }
}
}

if (SEQUENTIAL_DETACH == ACTIVATED) { 
  ali_debug_pprint("sending detach command\n");
  scenario_send_packet(initialUserID, NUMBER_OF_USERS_PER_ROUND, DETACH_COMMAND, detachCommandStartTimes);
  //printf ("nano: %ld\n", tsp.tv_nsec);
  //printf ("second: %ld\n", tsp.tv_sec);
}
//TODO: Change the repetitive code for delay to a inline function or macro or something similar
//It is not only repetitive but also it can be wrong if the second wrap arounds.
delayNanoSec(WAIT_BETWEEN_ROUNDS);
   clock_gettime (CLOCK_REALTIME, &sleepStartTime);
     for (w = 0; w < 1000000; w++)
     {
     clock_gettime (CLOCK_REALTIME, &sleepDuringTime);
     if (sleepDuringTime.tv_nsec - sleepStartTime.tv_nsec > WAIT_BETWEEN_ROUNDS)
     {
//printf ("larger %d\n",w);
break;
}
}

}*/
/* it seems there is no need to have multi thread!
   unsigned scenario_core = 0;
   scenario_core = rte_lcore_id();
   scenario_core = rte_get_next_lcore(scenario_core, 1,1);
   rte_eal_remote_launch( scenario_packet_sender, NULL, scenario_core);*/
srand(time(NULL));
printf("start initializaztion\n");
int j = 0;
int numOfUsersInDisc = NUMBER_OF_USERS;
int numOfUsersInConn = 0;
int numOfUsersInIdle = 0;
int numberOfHandovers = 0;
for (j=0; j < NUMBER_OF_USERS; j++) {
  usersState[j].imsi = j;
  usersState[j].currentState = SCENARIO_STATE_DISC;
  usersState[j].L1RatePerSecond = L1_DISC_TO_CONN_RATE;
  usersState[j].L2RatePerSecond = L2_CONN_TO_IDLE_RATE;
  usersState[j].L3RatePerSecond = L3_IDLE_TO_CONN_RATE;
  usersState[j].L4RatePerSecond = L4_CONN_TO_CONN_RATE;
  usersState[j].L5RatePerSecond = L5_CONN_TO_DISC_RATE;
  //TODO: I should think about it to make sure the following line is the best way to set initial clock
  clock_gettime(CLOCK_REALTIME, &usersState[j].lastCheck);
}

//struct onvm_nf_info *nf_info;
onvm_nflib_nf_ready(nf_info);

printf("before going in the while 1\n");
//TODO: for debugging purposes the while condition is changed from always true!
printf ("ali change while condition back to always true\n");
int while_counter = 0;
while (/*numOfUsersInConn < 5*/1) {

  if (while_counter <= SCENARIO_RATE_STEPS) {
    while_counter++;  
    dynamic_scenario_rate_multiplier = SCENARIO_DEFAULT_RATE_MULTIPLIER * while_counter / SCENARIO_RATE_STEPS;
  }
  int i;
  ali_debug_print("No of users in disc %d, in conn %d, in idle %d and No of Handovers %d\n", numOfUsersInDisc, numOfUsersInConn, numOfUsersInIdle, numberOfHandovers);
  if (SHOW_USER_STATS_IN_SCEN_GEN == ENABLED) {
    user_stats_display(numOfUsersInDisc, numOfUsersInConn, numOfUsersInIdle, numberOfHandovers, while_counter);
  }
  for (i=0; i < NUMBER_OF_USERS; i++) {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    long timeDiff = returnNanoDifference (usersState[i].lastCheck, now);
    usersState[i].lastCheck = now;
    float randomFloat = (float) rand() / (float) RAND_MAX;
    if (usersState[i].currentState == SCENARIO_STATE_DISC) {
      float L1Chance = 1.0 - exp (-1 * dynamic_scenario_rate_multiplier * usersState[i].L1RatePerSecond * (1.0 * timeDiff / 1000000000));
      //printf("we are in disc, timediff %l l1chance \n", timeDiff, );
      if (randomFloat < L1Chance) {
	scenario_send_packet (usersState[i].imsi, 1, NEW_USER_COMMAND, startTimes);
	numOfUsersInDisc--;
	numOfUsersInConn++;
	usersState[i].currentState = SCENARIO_STATE_CONN;
      }
    }
    else if (usersState[i].currentState == SCENARIO_STATE_CONN) {
      float L5Chance = 1.0 - exp (-1 * dynamic_scenario_rate_multiplier * usersState[i].L5RatePerSecond * (1.0 * timeDiff / 1000000000));
      float L2Chance = 1.0 - exp (-1 * dynamic_scenario_rate_multiplier * usersState[i].L2RatePerSecond * (1.0 * timeDiff / 1000000000));
      float L4Chance = 1.0 - exp (-1 * dynamic_scenario_rate_multiplier * usersState[i].L4RatePerSecond * (1.0 * timeDiff / 1000000000));
      if ( L2Chance + L4Chance + L5Chance > 1) {
	printf ("Error! The total chance of L2+L4+L5 is larger than one \n");
      } else {
	if (randomFloat < L2Chance) {
	scenario_send_packet (usersState[i].imsi, 1, ACTIVE_TO_IDLE_COMMAND, startTimes);
	  numOfUsersInConn--;
	  numOfUsersInIdle++;
	  usersState[i].currentState = SCENARIO_STATE_IDLE;
	} else if (randomFloat < L2Chance + L4Chance) {
	  	scenario_send_packet (usersState[i].imsi, 1, HANDOVER_COMMAND, startTimes);

	  // Handover happened
	  numberOfHandovers++;
	} else if (randomFloat < L2Chance + L4Chance + L5Chance) {
	scenario_send_packet (usersState[i].imsi, 1, DETACH_COMMAND, startTimes);

	  numOfUsersInDisc++;
	  numOfUsersInConn--;
	  usersState[i].currentState = SCENARIO_STATE_DISC;
	}
      }
    }
    else if (usersState[i].currentState == SCENARIO_STATE_IDLE) {
      float L3Chance = 1.0 - exp (-1 * dynamic_scenario_rate_multiplier * usersState[i].L3RatePerSecond * (1.0 * timeDiff / 1000000000));
      if (randomFloat < L3Chance) {
	scenario_send_packet (usersState[i].imsi, 1, IDLE_TO_ACTIVE_COMMAND, startTimes);

	numOfUsersInIdle--;
	numOfUsersInConn++;
	usersState[i].currentState = SCENARIO_STATE_CONN;
      }
    }
    else {
      printf("Error! User is in unknown state\n");
    }
  }
}
onvm_nflib_run (nf_info, &packet_handler);
FILE *f = fopen ("output.txt", "w");
if (f == NULL)
{
  printf ("Error opening file!\n");
  exit (1);
}
for (j = 0; j < USER_STATE_SIZE; j++)
{
  fprintf (f, "userID %d startnano %ld  startsec %ld hsnano %ld hssec %ld\n", j, startTimes[j].tv_nsec, startTimes[j].tv_sec, handoverStartTimes[j].tv_nsec, handoverStartTimes[j].tv_sec);
}
fclose (f);

printf ("If we reach here, program is ending");
return 0;
}
