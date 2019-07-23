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
#include <rte_mempool.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "lteCore.h"

#define NF_TAG "simple_forward"

//struct onvm_nf_info *nf_info;


/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

/* number of package between each print */
static uint32_t print_delay = 1000000;
static struct CleaneNBState myState;
// Probably need to add IP to IP mapping from user IP to core IP
//static uint16_t s1dlCounter = 0;
//static uint32_t s1dltos1ul [USER_STATE_SIZE];
// TODO: iptoip should be used for data plane
//static uint32_t iptoip[USER_STATE_SIZE];
//static uint32_t iptos1ul[USER_STATE_SIZE];
// TODO: users should be used
//static struct lteENBUserState users[USER_STATE_SIZE];

#if STORE_RESULTS_ENB == ENABLED
static struct timespec* startTimes_t;
static struct timespec* endTimes_t;
static struct timespec* startTimes_h;
static struct timespec* endTimes_h;
static struct timespec* startTimes_a;
static struct timespec* endTimes_a;
static struct timespec* startTimes_i;
static struct timespec* endTimes_i;
static struct timespec* startTimes_d;
static struct timespec* endTimes_d;
#endif
static struct lteENBUserState* users;

#if STORE_RESULTS_ENB == ENABLED
static struct timespec* hstartTimes_t;
static struct timespec* hendTimes_t;
static struct timespec* hstartTimes_h;
static struct timespec* hendTimes_h;
static struct timespec* hstartTimes_a;
static struct timespec* hendTimes_a;
static struct timespec* hstartTimes_i;
static struct timespec* hendTimes_i;
static struct timespec* hstartTimes_d;
static struct timespec* hendTimes_d;
#endif

static uint32_t rejectedAttach = 0;
static uint32_t rejectedHandover = 0;
static uint32_t rejectedDetach = 0;
static uint32_t rejectedItoA = 0;
static uint32_t rejectedAtoI = 0;








static uint32_t destination;

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
packet_handler (struct rte_mbuf *pkt, struct onvm_pkt_meta *meta, __attribute__((unused)) struct onvm_nf_info *nf_info)
{
  //ali_debug_print_user(userID,"debugtest %i", 11);
  //printf("%i",ALIDEBUG);
  static uint32_t counter = 0;
  if (++counter == print_delay && SHOW_PACKET_STATS != DISABLED)
  {
    do_stats_display (pkt);
    counter = 0;
  }

  if (counter % 100000 == 9999) {
    //printf ("printing mem stat\n");

    // save socket stat to file. For some reason the original function with same functionality was making NF stop sometimes.
    /*
       struct rte_malloc_socket_stats sock_stats;
       int op = rte_malloc_get_socket_stats (0, &sock_stats);
       if ( op >= 0) {
       printf ("socket stat was successful\n");
    //printf( "Socket:%u\n", socket);
    printf( "\tHeap_size:%zu,\n", sock_stats.heap_totalsz_bytes);
    //printf( "Socket:%u\n", socket);
    printf( "\tHeap_size:%zu,\n", sock_stats.heap_totalsz_bytes);
    printf( "\tFree_size:%zu,\n", sock_stats.heap_freesz_bytes);
    printf( "\tAlloc_size:%zu,\n", sock_stats.heap_allocsz_bytes);
    printf( "\tGreatest_free_size:%zu,\n",
    sock_stats.greatest_free_size);
    printf( "\tAlloc_count:%u,\n",sock_stats.alloc_count);
    printf( "\tFree_count:%u,\n", sock_stats.free_count);
    } else {
    printf ("socket stat was unsuccessful\n");
    }
     */

    //rte_mempool_dump (file, rte_mempool*)

    //FILE *fp;
    //fp = fopen("poolStat.txt", "a");
    //rte_mempool_list_dump (fp);


    struct rte_mempool *pktmbuf_pool;
    pktmbuf_pool = rte_mempool_lookup (PKTMBUF_POOL_NAME ) ;
    if (pktmbuf_pool == NULL ) {
      printf ("null was returned for the pool pointer \n");
    }


    // rte_mempool_full ( const struct rte_mempool *	mp  ) 
    //show how much mbuf exist and available in mbuff pools
    //unsigned int inuse =  rte_mempool_free_count ( pktmbuf_pool); 
    //unsigned int available =  rte_mempool_count ( pktmbuf_pool);
    // rte_mempool_avail_count and rte_mempool_in_use_count respectively.
    unsigned int inuse = rte_mempool_in_use_count (pktmbuf_pool);
    unsigned int available = rte_mempool_avail_count(pktmbuf_pool);
    ali_debug_print ("in use is %u and avail is %u \n", inuse, available);
    if (available < 10000) {
      critical_print("low on memory! avail is %u \n", available);
    }

    //FILE *fp;
    //fp = fopen("memStat.txt", "a");
    //rte_malloc_dump_stats(fp, NULL);
    //printf ("after printing mem stat\n");
  }

  if (pkt->port == DATA_PACKET_PORT)
    //new packet coming from lte data
  {
    ali_debug_pprint ("new data packet received\n");
    struct ipv4_hdr *iph;
    iph = (struct ipv4_hdr *) (rte_pktmbuf_mtod (pkt,char *));
    uint32_t tempip = rte_be_to_cpu_32 (iph->src_addr);
    ali_debug_print2 ("resulted ip %lu\n", (unsigned long) tempip - PGW1_FIRST_IP);
    // uint32_t tempDestIp = iptoip[tempip - PGW1_FIRST_IP];
    ali_debug_pprint ("before gre\n");
    // ali_debug_print2 ("temp s1ul %lu", (unsigned long) temps1ul);
    // addGREHeader (pkt, temps1ul);
    ali_debug_pprint ("before ip\n");
    prependIPHeader (pkt, ENB1IP, EUC1IP, IP_TYPE_GUSER);
    ali_debug_pprint ("before ethernet\n");
    prependETHF2toF3 (pkt);
    ali_debug_pprint ("data message is being forwarded!\n");
    //send directly to port
    //printf ("check 3\n");
    //struct onvm_pkt_meta *pmeta;
    //pmeta = onvm_get_pkt_meta (pkt);
    meta->destination = 0;
#if CLEANG_MULTIPORT == ACTIVATED
    meta->destination = counter % 3;
    printf ("coutner is %i \n", counter);
#endif
    meta->action = ONVM_NF_ACTION_OUT;
    //printf ("check 4\n");
    return 0;

  }
  if (pkt->port == COMMAND_MESSAGE_PORT)
    //scenario generator has send a new user command
  {
    ali_debug_pprint ("command from scen gen received\n");
    struct scenarioMessage *sm;
    sm = (struct scenarioMessage *) (rte_pktmbuf_mtod (pkt,char *));
    ali_debug_print2 ("command is: %i\n", sm->command);
    ali_debug_print2 ("userID Havij is : %i\n", sm->userID);
    int tempUserID = sm->userID;

    int tempImsi = tempUserID;
    if (tempImsi > USER_STATE_SIZE)
      critical_print ("large imsi size!! %u\n", tempImsi);

    meta->action = ONVM_NF_ACTION_DROP;
    //clock_gettime(CLOCK_REALTIME, &startTimes[tempUserID]);
    //printf ("check 1\n");
    if (sm->command == NEW_USER_COMMAND){

      if (users[tempImsi].state == ENB_STATE_DISC) {

#if STORE_RESULTS_ENB == ENABLED
	if (startTimes_t[tempImsi].tv_nsec != 0) {
	  hstartTimes_t[tempImsi] = startTimes_t[tempImsi];
	  hendTimes_t[tempImsi] = endTimes_t[tempImsi];
	  endTimes_t[tempImsi].tv_sec = 0;
	  endTimes_t[tempImsi].tv_nsec = 0;
	}
	clock_gettime(CLOCK_REALTIME, &startTimes_t[tempImsi]);
#endif
	//clock_gettime(CLOCK_REALTIME, &startTimes_t[tempUserID]);
	struct tLTE5C *t5;
	ali_debug_pprint ("new user command received\n");
	//ali_debug_print2 ("am size: %lu\n", sizeof (struct attachMessage));
	ali_debug_print2 ("sm size: %lu\n", sizeof (struct scenarioMessage));
	ali_debug_print2 ("headroom: %i\n", rte_pktmbuf_headroom (pkt));
	ali_debug_print2 ("tailroom: %i\n", rte_pktmbuf_tailroom (pkt));
	rte_pktmbuf_append (pkt, sizeof (struct tLTE5C) - sizeof (struct scenarioMessage));
	t5 = (struct tLTE5C *) (rte_pktmbuf_mtod (pkt,char *));
	ali_debug_pprint2 ("check 1.5\n");
	t5->messageCode = TLTE5_MESSAGE_CODE_C;	//1 is the code for attach
	//printf ("check 1.6\n");
	t5->imsi = tempUserID;
	t5->tai = 7;
	t5->ecgi = 7;
	/*
	printf ("size of void* is%lu\n", sizeof (void*));
	printf ("size of int is %lu\n", sizeof (int));
	printf ("size of struct tLTE5C is %lu\n", sizeof(struct tLTE5C));
	printf ("data address is %p\n", (void*) rte_pktmbuf_mtod_offset(pkt, void *,0));
	printf ("message code address is %p\n",(void*) &t5->messageCode);
	printf ("imsi address is %p\n",(void*) &t5->imsi);
	printf ("tai address is %p\n", (void*) &t5->tai);
	printf ("ecgi address is %p\n",(void*) &t5->ecgi);
	*/
	//printf ("check 2\n");
	//snprintf ( am->autn, 256, "%s", "the first attach message" );

	// add ip header, 10.0.0.6
	prependIPHeader (pkt, ENB1IP, EUC1IP, IP_TYPE_NAS);
	prependETHF2toF3 (pkt);
	ali_debug_pprint ("attach message is being sent!\n");
	//send directly to port
	//printf ("check 3\n");
	//struct onvm_pkt_meta *pmeta;
	//pmeta = onvm_get_pkt_meta (pkt);
	meta->destination = 0;
#if CLEANG_MULTIPORT == ACTIVATED
	meta->destination = counter % 3;
#endif
	meta->action = ONVM_NF_ACTION_OUT;
	users[tempImsi].state = ENB_STATE_TRANSITION_T;
	//printf ("check 4\n");
	return 0;
      } else {
	critical_print ("%u is state, not in proper state for attach user %u\n", users[tempImsi].state, tempImsi);
	rejectedAttach++;
      }
    }

    if (sm->command == HANDOVER_COMMAND){

      if (users[tempImsi].state == ENB_STATE_CONN) {

#if STORE_RESULTS_ENB == ENABLED
	if (startTimes_h[tempImsi].tv_nsec != 0) {
	  hstartTimes_h[tempImsi] = startTimes_h[tempImsi];
	  hendTimes_h[tempImsi] = endTimes_h[tempImsi];
	  endTimes_h[tempImsi].tv_sec = 0;
	  endTimes_h[tempImsi].tv_nsec = 0;
	}
	clock_gettime(CLOCK_REALTIME, &startTimes_h[tempImsi]);
#endif
	//  clock_gettime(CLOCK_REALTIME, &startTimes_h[tempUserID]);

	struct  hLTE2C *h2c;
	ali_debug_pprint_user(tempUserID,"handover command received\n");
	if (sizeof (struct hLTE2C) - sizeof (struct scenarioMessage) > 0)
	{               // more space is needed in the packet
	  rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct hLTE2C) - sizeof (struct scenarioMessage)));
	  ali_debug_pprint2 ("increasing the size\n");
	}
	else
	{               // the packet is already larger than it shold be
	  rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct scenarioMessage) - sizeof (struct hLTE2C)));
	  ali_debug_pprint2 ("decreasing the size\n");
	}

	h2c = (struct hLTE2C *) (rte_pktmbuf_mtod (pkt,char *));
	h2c->messageCode = HLTE2_MESSAGE_CODE_C;     //1 is the code for attach
	//printf ("check 1.6\n");
	h2c->imsi = tempUserID;

	//h2c->targetENB = 2;
	//snprintf ( am->autn, 256, "%s", "the first attach message" );

	// add ip header, 10.0.0.6
	//	prependIPHeader (pkt, ENB1IP, myState.coreIPAddresses[0], IP_TYPE_NAS);
	prependIPHeader (pkt, ENB1IP, EUC1IP, IP_TYPE_NAS);

	prependETHF2toF3 (pkt);
	ali_debug_pprint ("Handover message is being sent!\n");
	//send directly to port
	//printf ("check 3\n");
	//struct onvm_pkt_meta *pmeta;
	//pmeta = onvm_get_pkt_meta (pkt);
	meta->destination = 0;
#if CLEANG_MULTIPORT == ACTIVATED
	meta->destination = counter % 3;
#endif
	meta->action = ONVM_NF_ACTION_OUT;
	//printf ("check 4\n");
	users[tempImsi].state = ENB_STATE_TRANSITION_H;

	return 0;

      } else {
	//	critical_pprint("not in proper state for handover\n");
	critical_print ("%u is state, not in proper state for handover user %u\n", users[tempImsi].state, tempImsi);
	rejectedHandover++;
      }
    }
    // detach commmand
    if (sm->command == DETACH_COMMAND){

      //TODO: are these two states are really allowed or one of them?
      if (users[tempImsi].state == ENB_STATE_IDLE || users[tempImsi].state == ENB_STATE_CONN) {

#if STORE_RESULTS_ENB == ENABLED
	if (startTimes_d[tempImsi].tv_nsec != 0) {
	  hstartTimes_d[tempImsi] = startTimes_d[tempImsi];
	  hendTimes_d[tempImsi] = endTimes_d[tempImsi];
	  endTimes_d[tempImsi].tv_sec = 0;
	  endTimes_d[tempImsi].tv_nsec = 0;
	}

	clock_gettime(CLOCK_REALTIME, &startTimes_d[tempImsi]);
#endif
	//clock_gettime(CLOCK_REALTIME, &startTimes_d[tempUserID]);

	struct  dLTE2C *d2c;
	ali_debug_pprint_user(tempUserID,"detach command received\n");
	if (sizeof (struct dLTE2C) - sizeof (struct scenarioMessage) > 0)
	{               // more space is needed in the packet
	  rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct dLTE2C) - sizeof (struct scenarioMessage)));
	  ali_debug_pprint2 ("increasing the size\n");
	}
	else
	{               // the packet is already larger than it shold be
	  rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct scenarioMessage) - sizeof (struct dLTE2C)));
	  ali_debug_pprint2 ("decreasing the size\n");
	}

	d2c = (struct dLTE2C *) (rte_pktmbuf_mtod (pkt,char *));
	d2c->messageCode = DLTE2_MESSAGE_CODE_C;     //1 is the code for attach
	//printf ("check 1.6\n");
	d2c->imsi = tempUserID;
	//d1->targetENB = 2;
	//snprintf ( am->autn, 256, "%s", "the first attach message" );

	// add ip header, 10.0.0.6
	prependIPHeader (pkt, ENB1IP, myState.coreIPAddresses[0], IP_TYPE_NAS);
	prependETHF2toF3 (pkt);
	ali_debug_pprint ("detach2 message is being sent to mme!\n");
	//send directly to port
	//printf ("check 3\n");
	struct onvm_pkt_meta *pmeta;
	pmeta = onvm_get_pkt_meta (pkt);
	pmeta->destination = 0;
#if CLEANG_MULTIPORT == ACTIVATED
	meta->destination = counter % 3;
#endif
	pmeta->action = ONVM_NF_ACTION_OUT;
	//printf ("check 4\n");
	//return 0;

	users[tempImsi].state = ENB_STATE_TRANSITION_D;
	return 0;
      } else {
	//critical_pprint("not in proper state for detach\n");
	critical_print ("%u is state, not in proper state for detach of user %u\n", users[tempImsi].state, tempImsi);
	rejectedDetach++;
      }
    }
    // idle to active command
    if (sm->command == IDLE_TO_ACTIVE_COMMAND){

      if (users[tempImsi].state == ENB_STATE_IDLE) {

#if STORE_RESULTS_ENB == ENABLED
	if (startTimes_i[tempImsi].tv_nsec != 0) {
	  hstartTimes_i[tempImsi] = startTimes_i[tempImsi];
	  hendTimes_i[tempImsi] = endTimes_i[tempImsi];
	  endTimes_i[tempImsi].tv_sec = 0;
	  endTimes_i[tempImsi].tv_nsec = 0;
	}

	clock_gettime(CLOCK_REALTIME, &startTimes_i[tempImsi]);
	//clock_gettime(CLOCK_REALTIME, &startTimes_i[tempUserID]);
#endif
	struct  iLTE5C *i5c;
	ali_debug_pprint_user(tempUserID,"idle to active command received\n");
	if (sizeof (struct iLTE5C) - sizeof (struct scenarioMessage) > 0)
	{               // more space is needed in the packet
	  rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct iLTE5C) - sizeof (struct scenarioMessage)));
	  ali_debug_pprint2 ("increasing the size\n");
	}
	else
	{               // the packet is already larger than it shold be
	  rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct scenarioMessage) - sizeof (struct iLTE5C)));
	  ali_debug_pprint2 ("decreasing the size\n");
	}

	i5c = (struct iLTE5C *) (rte_pktmbuf_mtod (pkt,char *));
	i5c->messageCode = ILTE5_MESSAGE_CODE_C;
	//printf ("check 1.6\n");
	i5c->imsi = tempUserID;
	//d1->targetENB = 2;
	//snprintf ( am->autn, 256, "%s", "the first attach message" );

	// add ip header, 10.0.0.6
	prependIPHeader (pkt, ENB1IP, myState.coreIPAddresses[0], IP_TYPE_NAS);
	prependETHF2toF3 (pkt);
	ali_debug_pprint ("idle to active5  message is being sent to mme!\n");
	//send directly to port
	//printf ("check 3\n");
	struct onvm_pkt_meta *pmeta;
	pmeta = onvm_get_pkt_meta (pkt);
	pmeta->destination = 0;
#if CLEANG_MULTIPORT == ACTIVATED
	meta->destination = counter % 3;
#endif
	pmeta->action = ONVM_NF_ACTION_OUT;
	//printf ("check 4\n");
	//return 0;

	users[tempImsi].state = ENB_STATE_TRANSITION_I;
	//TODO: Are these reutrn 0s are necessary here or not? inconsistent with lte enb.
	return 0;
	//printf ("check 4\n");
      } else {
	//critical_pprint ("not in proper state for idle to active\n");
	critical_print ("%u is state, not in proper state for itoa of user %u\n", users[tempImsi].state, tempImsi);
	rejectedItoA++;
      }
    }
    // active to idle command
    if (sm->command == ACTIVE_TO_IDLE_COMMAND){

      if (users[tempImsi].state == ENB_STATE_CONN) {


#if STORE_RESULTS_ENB == ENABLED

	if (startTimes_a[tempImsi].tv_nsec != 0) {
	  hstartTimes_a[tempImsi] = startTimes_a[tempImsi];
	  hendTimes_a[tempImsi] = endTimes_a[tempImsi];
	  endTimes_a[tempImsi].tv_sec = 0;
	  endTimes_a[tempImsi].tv_nsec = 0;
	}

	clock_gettime(CLOCK_REALTIME, &startTimes_a[tempImsi]);
	//      clock_gettime(CLOCK_REALTIME, &startTimes_a[tempUserID]);
#endif
	struct  aLTE1C *a1;
	ali_debug_pprint_user(tempUserID,"active to idle command received\n");
	if (sizeof (struct aLTE1C) - sizeof (struct scenarioMessage) > 0)
	{               // more space is needed in the packet
	  rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct aLTE1C) - sizeof (struct scenarioMessage)));
	  ali_debug_pprint2 ("increasing the size\n");
	}
	else
	{               // the packet is already larger than it shold be
	  rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct scenarioMessage) - sizeof (struct aLTE1C)));
	  ali_debug_pprint2 ("decreasing the size\n");
	}

	a1 = (struct aLTE1C *) (rte_pktmbuf_mtod (pkt,char *));
	a1->messageCode = ALTE1_MESSAGE_CODE_C;
	//printf ("check 1.6\n");
	a1->imsi = tempUserID;
	//d1->targetENB = 2;
	//snprintf ( am->autn, 256, "%s", "the first attach message" );

	// add ip header, 10.0.0.6
	prependIPHeader (pkt, ENB1IP, myState.coreIPAddresses[0], IP_TYPE_NAS);
	prependETHF2toF3 (pkt);
	ali_debug_pprint ("active to idle1 is being sent to mme!\n");
	//send directly to port
	//printf ("check 3\n");
	struct onvm_pkt_meta *pmeta;
	pmeta = onvm_get_pkt_meta (pkt);
	pmeta->destination = 0;
#if CLEANG_MULTIPORT == ACTIVATED
	meta->destination = counter % 3;
#endif
	pmeta->action = ONVM_NF_ACTION_OUT;
	//printf ("check 4\n");
	// return 0;

	users[tempImsi].state = ENB_STATE_TRANSITION_A;
	return 0;
      } else {
	//critical_pprint ("not in proper state for active to idle\n");
	critical_print ("%u is state, not in proper state for aToI of user%u\n", users[tempImsi].state, tempImsi);
	rejectedAtoI++;
      }
    }
    ali_debug_pprint("none of the commands is matched!! or incorrect state!\n");
    return 0;
  }
  else
  {				//if it is no comming from scenario generator
    //check to see if it is a NAS message
    struct ipv4_hdr *iph;
    iph = (struct ipv4_hdr *) rte_pktmbuf_mtod (pkt,char *);



    if (iph->next_proto_id == IP_TYPE_GUSER)
    {
      ali_debug_pprint ("a data  message is received\n");
      ali_debug_print ("packet port is %d\n", pkt->port);
      // remove the ip header
      rte_pktmbuf_adj (pkt, 20);
      //rte_pktmbuf_adj (pkt, sizeof (struct GTPUHeader));
      //pkt->port = 11;
      meta->destination = LTE_DATA_SERVICE_ID;
      meta->action = ONVM_NF_ACTION_TONF;
      return 0;
    }

    //		if (iph->next_proto_id == IP_TYPE_NAS)
    //		{
    ali_debug_pprint ("a nas message is received\n");
    // remove the ip header
    rte_pktmbuf_adj (pkt, 20);
    if (*rte_pktmbuf_mtod (pkt,char *) == TLTE8_MESSAGE_CODE_C)  
    {
      ali_debug_pprint ("TLTE8C received \n");
      struct tLTE8C *t8c = (struct tLTE8C *) rte_pktmbuf_mtod (pkt,char *);
      uint32_t tempImsi = t8c->imsi;

#if STORE_RESULTS_ENB == ENABLED
      clock_gettime(CLOCK_REALTIME, &endTimes_t[tempImsi]);
#endif
      users[tempImsi].state = ENB_STATE_CONN;
      uint32_t tempIP = t8c->ip;
      /*   users[tempImsi].state = ENB_STATE_HANDOVER;
	   s1dltos1ul[users[tempImsi].s1dl] = l7->s1ul;
	   ali_debug_pprint2 ("before changing the size\n");
	   if (sizeof (struct hLTE9) - sizeof (struct hLTE7) > 0)
	   {               // more space is needed in the packet
	   rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct hLTE9) - sizeof (struct hLTE7)));
	   ali_debug_pprint2 ("increasing the size\n");
	   }
	   else
	   {               // the packet is already larger than it shold be
	   rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct hLTE7) - sizeof (struct hLTE9)));
	   ali_debug_pprint2 ("decreasing the size\n");
	   }
	   l9 = (struct hLTE9 *) rte_pktmbuf_mtod (pkt,char *);
	   ali_debug_pprint2 ("after setting are\n");
	   l9->messageCode = HLTE9_MESSAGE_CODE;
	   ali_debug_pprint2 ("after first change in are\n");
	   l9->imsi = tempImsi;
      //snprintf (are->res, 256, "%s", "This is res!");
      prependIPHeader (pkt, ENB1IP, MME1IP, IP_TYPE_NAS);
      prependETHF2toF3 (pkt);
      meta->destination = 0;*/
      meta->action = ONVM_NF_ACTION_DROP;
      ali_debug_pprint ("attach complete! drop the packet \n");
      if (SEND_DATA_PACKETS == ACTIVATED) {
	//send command to lte data to start sending data
	struct rte_mempool *pktmbuf_pool;
	struct rte_mbuf *newpkt;
	pktmbuf_pool = rte_mempool_lookup (PKTMBUF_POOL_NAME);
	if (pktmbuf_pool == NULL)
	{
	  ali_debug_pprint("cannot find poooool!! exit!!\n");
	  rte_exit (EXIT_FAILURE, "Cannot find mbuf pool!\n");
	}
	ali_debug_pprint ("sending command to start data\n");
	struct onvm_pkt_meta *pmeta;
	ali_debug_pprint("before alloc\n");
	newpkt = rte_pktmbuf_alloc (pktmbuf_pool);
	ali_debug_pprint("after alloc\n");
	struct sendDataCommand *sdc;
	sdc = (struct sendDataCommand *) rte_pktmbuf_prepend (newpkt, sizeof (struct sendDataCommand));
	sdc->commandCode = SEND_DATA_COMMAND;
	//printf ("sending data command!\n");
	sdc->ip = tempIP;
	sdc->imsi = tempImsi;
	//snprintf ( ar->autn, 256, "%s", "This is autn!" );
	//prependIPHeader (newpkt, MME1IP, ENB1IP, IP_TYPE_NAS);
	//prependETHF3toF2(newpkt);
	//fill it here
	//printf ("HAVIJ sending command to send data\n");
	//usleep (10000000);
	pmeta = onvm_get_pkt_meta (newpkt);
	newpkt->port = DATA_COMMAND_PORT;
	pmeta->destination = LTE_DATA_SERVICE_ID;
	pmeta->action = ONVM_NF_ACTION_TONF;
	onvm_nflib_return_pkt (nf_info,newpkt);
	ali_debug_pprint_user(tempImsi,"sending command to data nf to send data packets");
	//			clock_gettime(CLOCK_REALTIME, &endTimes_t[tempImsi]);
      }

      return 0;
    }
    // idle to active 6 
    if (*rte_pktmbuf_mtod (pkt,char *) == HLTE5_MESSAGE_CODE_C)  
    {
      ali_debug_pprint ("HLTE5C is received \n");
      struct hLTE5C *h5c = (struct hLTE5C *) rte_pktmbuf_mtod (pkt,char *);
      uint32_t tempImsi = h5c->imsi;
      struct hLTE7C *h7c;
      //users[tempImsi].state = ENB_STATE_HANDOVER;
      //s1dltos1ul[users[tempImsi].s1dl] = l7->s1ul;
      ali_debug_pprint2 ("before changing the size\n");
      if (sizeof (struct hLTE7C) - sizeof (struct hLTE5C) > 0)
      {               // more space is needed in the packet
	rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct hLTE7C) - sizeof (struct hLTE5C)));
	ali_debug_pprint2 ("increasing the size\n");
      }
      else
      {               // the packet is already larger than it shold be
	rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct hLTE5C) - sizeof (struct hLTE7C)));
	ali_debug_pprint2 ("decreasing the size\n");
      }
      h7c = (struct hLTE7C *) rte_pktmbuf_mtod (pkt,char *);
      ali_debug_pprint2 ("after setting are\n");
      h7c->messageCode = HLTE7_MESSAGE_CODE_C;
      ali_debug_pprint2 ("after first change in are\n");
      h7c->imsi = tempImsi;
      //snprintf (are->res, 256, "%s", "This is res!");
      prependIPHeader (pkt, ENB1IP, EUC1IP, IP_TYPE_NAS);
      prependETHF2toF3 (pkt);
      meta->destination = 0;
#if CLEANG_MULTIPORT == ACTIVATED
      meta->destination = counter % 3;
#endif
      meta->action = ONVM_NF_ACTION_OUT;
      ali_debug_pprint ("hlte7 is being sent to Core\n");
      return 0;
    }

    if (*rte_pktmbuf_mtod (pkt,char *) == HLTE11_MESSAGE_CODE_C)  
    {
      ali_debug_pprint ("virtual HLTE11C is received \n");
      struct hLTE11C *h11c = (struct hLTE11C *) rte_pktmbuf_mtod (pkt,char *);
      uint32_t tempImsi = h11c->imsi;
      users[tempImsi].state = ENB_STATE_CONN;

#if STORE_RESULTS_ENB == ENABLED
      clock_gettime(CLOCK_REALTIME, &endTimes_h[tempImsi]);
#endif
      /*	struct hLTE5C *h5c = (struct hLTE5C *) rte_pktmbuf_mtod (pkt,char *);
		uint32_t tempImsi = h5c->imsi;
		struct hLTE7C *h7c;
      //users[tempImsi].state = ENB_STATE_HANDOVER;
      //s1dltos1ul[users[tempImsi].s1dl] = l7->s1ul;
      ali_debug_pprint2 ("before changing the size\n");
      if (sizeof (struct hLTE7C) - sizeof (struct hLTE5C) > 0)
      {               // more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct hLTE7C) - sizeof (struct hLTE5C)));
      ali_debug_pprint2 ("increasing the size\n");
      }
      else
      {               // the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct hLTE5C) - sizeof (struct hLTE7C)));
      ali_debug_pprint2 ("decreasing the size\n");
      }
      h7c = (struct hLTE7C *) rte_pktmbuf_mtod (pkt,char *);
      ali_debug_pprint2 ("after setting are\n");
      h7c->messageCode = HLTE7_MESSAGE_CODE_C;
      ali_debug_pprint2 ("after first change in are\n");
      h7c->imsi = tempImsi;
      //snprintf (are->res, 256, "%s", "This is res!");
      prependIPHeader (pkt, ENB1IP, EUC1IP, IP_TYPE_NAS);
      prependETHF2toF3 (pkt);
      meta->destination = 0;*/
      meta->action = ONVM_NF_ACTION_DROP;
      ali_debug_pprint ("virtuall hlte11c is being dropped\n");
      return 0;
    }


    // d8
    if (*rte_pktmbuf_mtod (pkt,char *) == DLTE5_MESSAGE_CODE_C)  
    {
      ali_debug_pprint ("DLTE5C received \n");
      struct dLTE5C *d5c = (struct dLTE5C *) rte_pktmbuf_mtod (pkt,char *);
      uint32_t tempImsi = d5c->imsi;
      //uint32_t tempIP = d5c->ip;

#if STORE_RESULTS_ENB == ENABLED
      clock_gettime(CLOCK_REALTIME, &endTimes_d[tempImsi]);
#endif

      users[tempImsi].state = ENB_STATE_DISC;

      /* struct dLTE8 *d8 = (struct dLTE8 *) rte_pktmbuf_mtod (pkt,char *);
	 uint32_t tempImsi = i6->imsi;
	 struct iLTE10 *i10;
      //users[tempImsi].state = ENB_STATE_HANDOVER;
      //s1dltos1ul[users[tempImsi].s1dl] = l7->s1ul;
      ali_debug_pprint2 ("before changing the size\n");
      if (sizeof (struct iLTE10) - sizeof (struct iLTE6) > 0)
      {               // more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct iLTE10) - sizeof (struct iLTE6)));
      ali_debug_pprint2 ("increasing the size\n");
      }
      else
      {               // the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct iLTE6) - sizeof (struct iLTE10)));
      ali_debug_pprint2 ("decreasing the size\n");
      }
      i10 = (struct iLTE10 *) rte_pktmbuf_mtod (pkt,char *);
      ali_debug_pprint2 ("after setting are\n");
      i10->messageCode = ILTE10_MESSAGE_CODE;
      ali_debug_pprint2 ("after first change in are\n");
      i10->imsi = tempImsi;
      //snprintf (are->res, 256, "%s", "This is res!");
      prependIPHeader (pkt, ENB1IP, MME1IP, IP_TYPE_NAS);
      prependETHF2toF3 (pkt);
      meta->destination = 0;*/
      meta->action = ONVM_NF_ACTION_DROP;
      ali_debug_pprint ("dlte5C is being dropped\n");
      if (SEND_DATA_PACKETS == ACTIVATED) {
	//send command to lte data to start sending data
	struct rte_mempool *pktmbuf_pool;
	struct rte_mbuf *newpkt;
	pktmbuf_pool = rte_mempool_lookup (PKTMBUF_POOL_NAME);
	if (pktmbuf_pool == NULL)
	{
	  ali_debug_pprint("cannot find poooool!! exit!!\n");
	  rte_exit (EXIT_FAILURE, "Cannot find mbuf pool!\n");
	}
	ali_debug_pprint ("Start sending command to stop data\n");
	struct onvm_pkt_meta *pmeta;
	ali_debug_pprint("before alloc\n");
	newpkt = rte_pktmbuf_alloc (pktmbuf_pool);
	ali_debug_pprint("after alloc\n");
	struct sendDataCommand *sdc;
	sdc = (struct sendDataCommand *) rte_pktmbuf_prepend (newpkt, sizeof (struct sendDataCommand));
	sdc->commandCode = STOP_DATA_COMMAND;
	//sdc->ip = tempIP;
	sdc->imsi = tempImsi;
	//snprintf ( ar->autn, 256, "%s", "This is autn!" );
	//prependIPHeader (newpkt, MME1IP, ENB1IP, IP_TYPE_NAS);
	//prependETHF3toF2(newpkt);
	//fill it here
	//printf ("HAVIJ sending command to send data\n");
	//usleep (10000000);
	pmeta = onvm_get_pkt_meta (newpkt);
	newpkt->port = DATA_COMMAND_PORT;
	pmeta->destination = LTE_DATA_SERVICE_ID;
	pmeta->action = ONVM_NF_ACTION_TONF;
	onvm_nflib_return_pkt (nf_info, newpkt);
	ali_debug_pprint("sending command to data nf to stop data packets");
	//			clock_gettime(CLOCK_REALTIME, &endTimes_t[tempImsi]);
      }

      return 0;
    }

    if (*rte_pktmbuf_mtod (pkt,char *) == ALTE2_MESSAGE_CODE_C)  
    {
      struct aLTE2C *a2c = (struct aLTE2C *) rte_pktmbuf_mtod (pkt,char *);
      uint32_t tempImsi = a2c->imsi;

      ali_debug_pprint ("ALTE2C received \n");

#if STORE_RESULTS_ENB == ENABLED
      clock_gettime(CLOCK_REALTIME, &endTimes_a[tempImsi]);
#endif
      users[tempImsi].state = ENB_STATE_IDLE;

      /* struct dLTE8 *d8 = (struct dLTE8 *) rte_pktmbuf_mtod (pkt,char *);
	 uint32_t tempImsi = i6->imsi;
	 struct iLTE10 *i10;
      //users[tempImsi].state = ENB_STATE_HANDOVER;
      //s1dltos1ul[users[tempImsi].s1dl] = l7->s1ul;
      ali_debug_pprint2 ("before changing the size\n");
      if (sizeof (struct iLTE10) - sizeof (struct iLTE6) > 0)
      {               // more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct iLTE10) - sizeof (struct iLTE6)));
      ali_debug_pprint2 ("increasing the size\n");
      }
      else
      {               // the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct iLTE6) - sizeof (struct iLTE10)));
      ali_debug_pprint2 ("decreasing the size\n");
      }
      i10 = (struct iLTE10 *) rte_pktmbuf_mtod (pkt,char *);
      ali_debug_pprint2 ("after setting are\n");
      i10->messageCode = ILTE10_MESSAGE_CODE;
      ali_debug_pprint2 ("after first change in are\n");
      i10->imsi = tempImsi;
      //snprintf (are->res, 256, "%s", "This is res!");
      prependIPHeader (pkt, ENB1IP, MME1IP, IP_TYPE_NAS);
      prependETHF2toF3 (pkt);
      meta->destination = 0;*/
      meta->action = ONVM_NF_ACTION_DROP;
      ali_debug_pprint ("alte2C is being dropped\n");
      if (SEND_DATA_PACKETS == ACTIVATED) {
	//send command to lte data to start sending data
	struct rte_mempool *pktmbuf_pool;
	struct rte_mbuf *newpkt;
	pktmbuf_pool = rte_mempool_lookup (PKTMBUF_POOL_NAME);
	if (pktmbuf_pool == NULL)
	{
	  ali_debug_pprint("cannot find poooool!! exit!!\n");
	  rte_exit (EXIT_FAILURE, "Cannot find mbuf pool!\n");
	}
	ali_debug_pprint ("Start sending command to stop data\n");
	struct onvm_pkt_meta *pmeta;
	ali_debug_pprint("before alloc\n");
	newpkt = rte_pktmbuf_alloc (pktmbuf_pool);
	ali_debug_pprint("after alloc\n");
	struct sendDataCommand *sdc;
	sdc = (struct sendDataCommand *) rte_pktmbuf_prepend (newpkt, sizeof (struct sendDataCommand));
	sdc->commandCode = STOP_DATA_COMMAND;
	//sdc->ip = tempIP;
	sdc->imsi = tempImsi;
	//snprintf ( ar->autn, 256, "%s", "This is autn!" );
	//prependIPHeader (newpkt, MME1IP, ENB1IP, IP_TYPE_NAS);
	//prependETHF3toF2(newpkt);
	//fill it here
	//printf ("HAVIJ sending command to send data\n");
	//usleep (10000000);
	pmeta = onvm_get_pkt_meta (newpkt);
	newpkt->port = DATA_COMMAND_PORT;
	pmeta->destination = LTE_DATA_SERVICE_ID;
	pmeta->action = ONVM_NF_ACTION_TONF;
	onvm_nflib_return_pkt (nf_info,newpkt);
	ali_debug_pprint("sending command to data nf to stop data packets");
	//			clock_gettime(CLOCK_REALTIME, &endTimes_t[tempImsi]);
      }

      return 0;
    }


    if (*rte_pktmbuf_mtod (pkt,char *) == ILTE7_MESSAGE_CODE_C)  
    {
      struct iLTE7C *i7c = (struct iLTE7C *) rte_pktmbuf_mtod (pkt,char *);
      uint32_t tempImsi = i7c->imsi;
      uint32_t tempIP = i7c->ip;
      ali_debug_pprint ("IaLTE7C received \n");

#if STORE_RESULTS_ENB == ENABLED
      clock_gettime(CLOCK_REALTIME, &endTimes_i[tempImsi]);
#endif

      users[tempImsi].state = ENB_STATE_CONN; 
      /*				   struct iLTE10 *i10;
      //users[tempImsi].state = ENB_STATE_HANDOVER;
      //s1dltos1ul[users[tempImsi].s1dl] = l7->s1ul;
      ali_debug_pprint2 ("before changing the size\n");
      if (sizeof (struct iLTE10) - sizeof (struct iLTE6) > 0)
      {               // more space is needed in the packet
      rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct iLTE10) - sizeof (struct iLTE6)));
      ali_debug_pprint2 ("increasing the size\n");
      }
      else
      {               // the packet is already larger than it shold be
      rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct iLTE6) - sizeof (struct iLTE10)));
      ali_debug_pprint2 ("decreasing the size\n");
      }
      i10 = (struct iLTE10 *) rte_pktmbuf_mtod (pkt,char *);
      ali_debug_pprint2 ("after setting are\n");
      i10->messageCode = ILTE10_MESSAGE_CODE;
      ali_debug_pprint2 ("after first change in are\n");
      i10->imsi = tempImsi;
      //snprintf (are->res, 256, "%s", "This is res!");
      prependIPHeader (pkt, ENB1IP, MME1IP, IP_TYPE_NAS);
      prependETHF2toF3 (pkt);
      meta->destination = 0;*/
      meta->action = ONVM_NF_ACTION_DROP;
      ali_debug_pprint ("ilte7C is being dropped\n");
      if (SEND_DATA_PACKETS == ACTIVATED) {
	//send command to lte data to start sending data
	struct rte_mempool *pktmbuf_pool;
	struct rte_mbuf *newpkt;
	pktmbuf_pool = rte_mempool_lookup (PKTMBUF_POOL_NAME);
	if (pktmbuf_pool == NULL)
	{
	  ali_debug_pprint("cannot find poooool!! exit!!\n");
	  rte_exit (EXIT_FAILURE, "Cannot find mbuf pool!\n");
	}
	ali_debug_pprint ("resume  sending command to start data\n");
	struct onvm_pkt_meta *pmeta;
	ali_debug_pprint("before alloc\n");
	newpkt = rte_pktmbuf_alloc (pktmbuf_pool);
	ali_debug_pprint("after alloc\n");
	struct sendDataCommand *sdc;
	sdc = (struct sendDataCommand *) rte_pktmbuf_prepend (newpkt, sizeof (struct sendDataCommand));
	sdc->commandCode = RESUME_DATA_COMMAND;
	sdc->ip = tempIP;
	sdc->imsi = tempImsi;
	//snprintf ( ar->autn, 256, "%s", "This is autn!" );
	//prependIPHeader (newpkt, MME1IP, ENB1IP, IP_TYPE_NAS);
	//prependETHF3toF2(newpkt);
	//fill it here
	//printf ("HAVIJ sending command to send data\n");
	//usleep (10000000);
	pmeta = onvm_get_pkt_meta (newpkt);
	newpkt->port = DATA_COMMAND_PORT;
	pmeta->destination = LTE_DATA_SERVICE_ID;
	pmeta->action = ONVM_NF_ACTION_TONF;
	onvm_nflib_return_pkt (nf_info,newpkt);
	ali_debug_pprint("sending RESUME command to data nf to send data packets");
	//			clock_gettime(CLOCK_REALTIME, &endTimes_t[tempImsi]);
      }

      return 0;
    }
  }

  //	}

  // unhandled pacekt
  ali_debug_print ("Unhandled packet Code: %i", 1);
  //meta->action = ONVM_NF_ACTION_TONF;
  meta->action = ONVM_NF_ACTION_DROP;
  meta->destination = destination;
  return 0;
}


  int
main (int argc, char *argv[])
{
  int arg_offset;

  const char *progname = argv[0];

  if ((arg_offset = onvm_nflib_init (argc, argv, NF_TAG, &nf_info)) < 0)
    return -1;
  argc -= arg_offset;
  argv += arg_offset;
  destination = nf_info->service_id + 1;

  if (parse_app_args (argc, argv, progname) < 0)
    rte_exit (EXIT_FAILURE, "Invalid command-line arguments\n");
  //AliMamad
  myState.noOfCores = 1;
  myState.coreIPAddresses[0] = IP_10_0_0_0 + 3;

#if STORE_RESULTS_ENB == ENABLED
  startTimes_t = calloc (USER_STATE_SIZE, sizeof(struct timespec));
  endTimes_t = calloc (USER_STATE_SIZE, sizeof(struct timespec));
  startTimes_h = calloc (USER_STATE_SIZE, sizeof(struct timespec));
  endTimes_h = calloc (USER_STATE_SIZE, sizeof(struct timespec));
  startTimes_a = calloc (USER_STATE_SIZE, sizeof(struct timespec));
  endTimes_a = calloc (USER_STATE_SIZE, sizeof(struct timespec));
  startTimes_i = calloc (USER_STATE_SIZE, sizeof(struct timespec));
  endTimes_i = calloc (USER_STATE_SIZE, sizeof(struct timespec));
  startTimes_d = calloc (USER_STATE_SIZE, sizeof(struct timespec));
  endTimes_d = calloc (USER_STATE_SIZE, sizeof(struct timespec));
#endif
  users = calloc ( USER_STATE_SIZE, sizeof(struct lteENBUserState));

#if STORE_RESULTS_ENB == ENABLED
  hstartTimes_t = calloc (USER_STATE_SIZE, sizeof(struct timespec));
  hendTimes_t = calloc (USER_STATE_SIZE, sizeof(struct timespec));
  hstartTimes_h = calloc (USER_STATE_SIZE, sizeof(struct timespec));
  hendTimes_h = calloc (USER_STATE_SIZE, sizeof(struct timespec));
  hstartTimes_a = calloc (USER_STATE_SIZE, sizeof(struct timespec));
  hendTimes_a = calloc (USER_STATE_SIZE, sizeof(struct timespec));
  hstartTimes_i = calloc (USER_STATE_SIZE, sizeof(struct timespec));
  hendTimes_i = calloc (USER_STATE_SIZE, sizeof(struct timespec));
  hstartTimes_d = calloc (USER_STATE_SIZE, sizeof(struct timespec));
  hendTimes_d = calloc (USER_STATE_SIZE, sizeof(struct timespec));
#endif
  printf ("Start setting up the initial state of the users...\n");
  int i = 0;
  for (i =0 ; i < USER_STATE_SIZE; i++)
  {
    users[i].state = ENB_STATE_DISC;
  }
  printf ("done setting up the initial state of the users!\n");



  onvm_nflib_run (nf_info, &packet_handler);
  printf ("done with running the NF\n");
#if STORE_RESULTS_ENB == ENABLED
  FILE *f = fopen("outputCleanEnb.txt", "w");
  if (f == NULL)
  {
    printf("Error opening file!\n");
    exit(1);
  }
  printSimulParams(f);
  printOutputEnb(f, startTimes_t, startTimes_a, startTimes_i, startTimes_d, startTimes_h, 
      hstartTimes_t, hstartTimes_a, hstartTimes_i, hstartTimes_d, hstartTimes_h,
      endTimes_t, endTimes_a, endTimes_i, endTimes_d, endTimes_h, 
      hendTimes_t, hendTimes_a, hendTimes_i, hendTimes_d, hendTimes_h);

  /*int j;
    for (j=0; j < USER_STATE_SIZE; j++)
    {
    fprintf(f, "userID %d ", j);
    fprintf(f, "start_n_t %ld end_n_t %ld  start_s_t %ld end_s_t %ld ", startTimes_t[j].tv_nsec, endTimes_t[j].tv_nsec, startTimes_t[j].tv_sec, endTimes_t[j].tv_sec);
    fprintf(f, "start_n_a %ld end_n_a %ld  start_s_a %ld end_s_a %ld ", startTimes_a[j].tv_nsec, endTimes_a[j].tv_nsec, startTimes_a[j].tv_sec, endTimes_a[j].tv_sec);
    fprintf(f, "start_n_i %ld end_n_i %ld  start_s_i %ld end_s_i %ld ", startTimes_i[j].tv_nsec, endTimes_i[j].tv_nsec, startTimes_i[j].tv_sec, endTimes_i[j].tv_sec);
    fprintf(f, "start_n_d %ld end_n_d %ld  start_s_d %ld end_s_d %ld ", startTimes_d[j].tv_nsec, endTimes_d[j].tv_nsec, startTimes_d[j].tv_sec, endTimes_d[j].tv_sec);
    fprintf(f, "start_n_h %ld end_n_h %ld  start_s_h %ld end_s_h %ld ", startTimes_h[j].tv_nsec, endTimes_h[j].tv_nsec, startTimes_h[j].tv_sec, endTimes_h[j].tv_sec);
    fprintf(f, "t_value %ld ", (startTimes_t[j].tv_sec == endTimes_t[j].tv_sec ? endTimes_t[j].tv_nsec - startTimes_t[j].tv_nsec : endTimes_t[j].tv_nsec - startTimes_t[j].tv_nsec + 1000000000));
    fprintf(f, "a_value %ld ", (startTimes_a[j].tv_sec == endTimes_a[j].tv_sec ? endTimes_a[j].tv_nsec - startTimes_a[j].tv_nsec : endTimes_a[j].tv_nsec - startTimes_a[j].tv_nsec + 1000000000));
    fprintf(f, "i_value %ld ", (startTimes_i[j].tv_sec == endTimes_i[j].tv_sec ? endTimes_i[j].tv_nsec - startTimes_i[j].tv_nsec : endTimes_i[j].tv_nsec - startTimes_i[j].tv_nsec + 1000000000));
    fprintf(f, "d_value %ld ", (startTimes_d[j].tv_sec == endTimes_d[j].tv_sec ? endTimes_d[j].tv_nsec - startTimes_d[j].tv_nsec : endTimes_d[j].tv_nsec - startTimes_d[j].tv_nsec + 1000000000));
    fprintf(f, "h_value %ld ", (startTimes_h[j].tv_sec == endTimes_h[j].tv_sec ? endTimes_h[j].tv_nsec - startTimes_h[j].tv_nsec : endTimes_h[j].tv_nsec - startTimes_h[j].tv_nsec + 1000000000));
    fprintf(f, "\n");
    }
   */
  fclose(f);
#endif
  printf ("If we reach here, program is ending");
  return 0;
}


/*
   copied text from prevous persion of clean_enb
   if (pkt->port == COMMAND_MESSAGE_PORT)
   {
//printf( "command received\n");
struct scenarioMessage *sm;
sm = (struct scenarioMessage *) (rte_pktmbuf_mtod (pkt,char *));
//printf ("command is: %i\n", sm->command);
//printf ("userID is : %i\n", sm->userID);
int tempUserID = sm->userID;
clock_gettime (CLOCK_REALTIME, &startTimes[tempUserID]);
struct attachMessage *am;
//printf ("check 1\n");
//printf ("am size: %lu\n", sizeof(struct attachMessage));
//printf ("sm size: %lu\n", sizeof(struct scenarioMessage));
//printf ("headroom: %i\n", rte_pktmbuf_headroom(pkt));
//printf ("tailroom: %i\n", rte_pktmbuf_tailroom(pkt));
rte_pktmbuf_append (pkt, sizeof (struct attachMessage) - sizeof (struct scenarioMessage));
am = (struct attachMessage *) (rte_pktmbuf_mtod (pkt,char *));
//printf ("check 1.5\n");
am->message_code = 1;	//1 is the code for attach
//printf ("check 1.6\n");
am->imsi = tempUserID;
am->tai = 7;
am->ecgi = 7;
am->rand = 7;
//printf ("check 2\n");
snprintf (am->autn, 256, "%s", "the first attach message");

// add ip header
struct ipv4_hdr *iph;
iph = (struct ipv4_hdr *) rte_pktmbuf_prepend (pkt, sizeof (struct ipv4_hdr));
iph->time_to_live = 50;
iph->dst_addr = rte_be_to_cpu_32 (myState.coreIPAddresses[0]);
iph->src_addr = rte_be_to_cpu_32 (167772166);	//10.0.0.6
iph->version_ihl = 69;	//verion 4 length 5 words167772162
struct ether_hdr *eh;
eh = (struct ether_hdr *) rte_pktmbuf_prepend (pkt, sizeof (struct ether_hdr));
//eh->ether_type = ETHER_TYPE_IPv4;
struct ether_addr s;
struct ether_addr d;

d.addr_bytes[0] = 0x8c;
d.addr_bytes[1] = 0xdc;
d.addr_bytes[2] = 0xd4;
d.addr_bytes[3] = 0xac;
d.addr_bytes[4] = 0xc2;
d.addr_bytes[5] = 0x10;

s.addr_bytes[0] = 0x8c;
s.addr_bytes[1] = 0xdc;
s.addr_bytes[2] = 0xd4;
s.addr_bytes[3] = 0xac;
s.addr_bytes[4] = 0xc0;
s.addr_bytes[5] = 0x94;

ether_addr_copy (&s, &eh->s_addr);
ether_addr_copy (&d, &eh->d_addr);

eh->ether_type = rte_be_to_cpu_16 (ETHER_TYPE_IPv4);
//printf("attach message sent!");
//send directly to port
//printf ("check 3\n");
struct onvm_pkt_meta *pmeta;
pmeta = onvm_get_pkt_meta (pkt);
pmeta->destination = 0;
pmeta->action = ONVM_NF_ACTION_OUT;
//printf ("check 4\n");
return 0;
}

//printf ("a packet received from core\n");
rte_pktmbuf_adj (pkt, 20);
//printf("size: %i\n", rte_pktmbuf_data_len(pkt));
//printf("the first char is %02x\n", *rte_ctrlmbuf_data(pkt));
if (*rte_pktmbuf_mtod (pkt,char *) == 2)	// it is an authenticationResponse command
{
  //printf("an authentication response is received!\n");
  //forward packet to replier to let him know start sending packets
  struct authenticationResponse *ar;
  ar = (struct authenticationResponse *) (rte_pktmbuf_mtod (pkt,char *));
  uint64_t tempUserID = ar->imsi;
  clock_gettime (CLOCK_REALTIME, &endTimes[tempUserID]);
  pkt->port = 6;
  meta->destination = 3;	//replier service id is 3
  meta->action = ONVM_NF_ACTION_TONF;
  return 0;
}

*/
