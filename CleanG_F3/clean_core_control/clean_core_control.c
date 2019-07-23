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
#include <rte_hash.h>

#define NF_TAG "simple_forward"

/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

/* number of package between each print */
static uint32_t print_delay = 1000000;
static struct CleaneNBState myState;
static uint32_t assignedIPCounter = 0;
#if CLEANG_MODE == MESSAGE_LESS
struct rte_hash* encap_hash = NULL;
#endif
#if CLEANG_EXTENDED_HASH == ACTIVATED
struct rte_hash* core_hash = NULL;
#endif
// TODO: Ali change enb states to core states
// Probably need to add IP to IP mapping from user IP to core IP
//static uint16_t s1dlCounter = 0;
//static uint32_t s1dltos1ul [USER_STATE_SIZE];
// TODO: iptoip should be used for data plane
//static uint32_t iptoip[USER_STATE_SIZE];
//static uint32_t iptos1ul[USER_STATE_SIZE];
// TODO: users should be used
//static struct lteENBUserState users[USER_STATE_SIZE];
//static struct timespec startTimes [USER_STATE_SIZE];
//static struct timespec endTimes [USER_STATE_SIZE];
static uint32_t destination;
#if COMPLETE_T_LOGGING == ACTIVATED
static struct timespec* ctl[COMPLETE_MAX_NUMBER_OF_MESSAGE_CODE];
#endif

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
  //ali_debug_print("debugtest %i", 11);
  //printf("%i",ALIDEBUG);
  static uint32_t counter = 0;
  if (++counter == print_delay && SHOW_PACKET_STATS != DISABLED)
  {
    do_stats_display (pkt);
    counter = 0;
  }
  if (counter % 10000 == 9999) {
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

    // rte_mempool_full ( const struct rte_mempool *  mp  )
    //show how much mbuf exist and available in mbuff pools
    //The next two lines are functions in previous version of DPDK
    //unsigned int inuse =  rte_mempool_free_count ( pktmbuf_pool);
    //unsigned int available =  rte_mempool_count ( pktmbuf_pool);
    unsigned int inuse = rte_mempool_in_use_count (pktmbuf_pool);
    unsigned int available = rte_mempool_avail_count(pktmbuf_pool);

    ali_debug_print ("in use is %u and avail is %u \n", inuse, available);
    if (available < 10000) {
      critical_print ("not enough memory buffer available! %u \n", available);
    }

    //FILE *fp;
    //fp = fopen("memStat.txt", "a");
    //rte_malloc_dump_stats(fp, NULL);
    //printf ("after printing mem stat\n");
  }


  //if it is no comming from scenario generator
  //check to see if it is a NAS message
  struct ipv4_hdr *iph;
  iph = (struct ipv4_hdr *) rte_pktmbuf_mtod (pkt,char *);
  if (iph->next_proto_id == IP_TYPE_NAS)
  {
    ali_debug_pprint ("a nas message is received\n");
    // remove the ip header
    rte_pktmbuf_adj (pkt, 20);
#if COMPLETE_T_LOGGING == ACTIVATED
    //#warning ("complete t is activated\n")
    uint32_t* tCommand = rte_pktmbuf_mtod_offset(pkt, uint32_t *,0);
    uint64_t* tImsi = rte_pktmbuf_mtod_offset(pkt, uint64_t *,IMSI_INDEX);

    /* FILE *fp;
       fp = fopen("dump.txt", "a");
       fprintf (fp, "dumping packet \n");
       rte_pktmbuf_dump(fp, pkt, pkt->pkt_len);
       fclose(fp);
     */
    ali_debug_print ("command is %u and imsi is %lu \n", *tCommand, *tImsi);
    clock_gettime(CLOCK_REALTIME, &ctl[*tCommand][*tImsi]);
#endif
    if (*rte_pktmbuf_mtod (pkt,char *) == TLTE5_MESSAGE_CODE_C)  
    {
      ali_debug_pprint ("TLTE5C received \n");
      struct tLTE5C *tc5 = (struct tLTE5C *) rte_pktmbuf_mtod (pkt,char *);
      uint32_t tempImsi = tc5->imsi;
      struct tLTE8C *tc8;
      //   users[tempImsi].state = ENB_STATE_HANDOVER;
      //     s1dltos1ul[users[tempImsi].s1dl] = l7->s1ul;
      //     ali_debug_pprint2 ("before changing the size\n");
      if (sizeof (struct tLTE8C) - sizeof (struct tLTE5C) > 0)
      {               // more space is needed in the packet
	rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct tLTE8C) - sizeof (struct tLTE5C)));
	ali_debug_pprint2 ("increasing the size\n");
      }
      else
      {               // the packet is already larger than it shold be
	rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct tLTE5C) - sizeof (struct tLTE8C)));
	ali_debug_pprint2 ("decreasing the size\n");
      }
      tc8 = (struct tLTE8C *) rte_pktmbuf_mtod (pkt,char *);
      ali_debug_pprint2 ("after setting are\n");
      tc8->messageCode = TLTE8_MESSAGE_CODE_C;
      ali_debug_pprint2 ("after first change in are\n");
      tc8->imsi = tempImsi;
      tc8->ip = PGW1_FIRST_IP + assignedIPCounter;
      assignedIPCounter++;
      //snprintf (are->res, 256, "%s", "This is res!");
      prependIPHeader (pkt, EUC1IP, ENB1IP, IP_TYPE_NAS);
      prependETHF2toF3 (pkt);
      meta->destination = CLEANG_TOWARD_ENB;
      meta->action = ONVM_NF_ACTION_OUT;


#if CLEANG_MODE == MESSAGE_BASED
      struct rte_mempool *pktmbuf_pool;
      struct rte_mbuf *newpkt;
      pktmbuf_pool = rte_mempool_lookup (PKTMBUF_POOL_NAME);
      if (pktmbuf_pool == NULL)
      {
	rte_exit (EXIT_FAILURE, "Cannot find mbuf pool!\n");
      }
      ali_debug_pprint ("Start sending packet to data path\n");
      struct onvm_pkt_meta *pmeta;
      newpkt = rte_pktmbuf_alloc (pktmbuf_pool);
      struct CoreDataPathSet *c;
      c = (struct CoreDataPathSet *) rte_pktmbuf_prepend (newpkt, sizeof (struct CoreDataPathSet));
      c->messageCode = SET_CORE_PATH_COMMAND;
      ali_debug_print_user(tempImsi, "message code for data command is: %u", c->messageCode);
      c->ueIP = tc8->ip;
      // TODO: Now assumed all the users are connected to enb1 first, it could be changed to dynamic.
      c->enbIP = ENB1IP;
      pmeta = onvm_get_pkt_meta (newpkt);
      // TODO: ALI use the define for the destination ID
      pmeta->destination = 1;
      newpkt->port = DATA_COMMAND_PORT;
      pmeta->action = ONVM_NF_ACTION_TONF;
      onvm_nflib_return_pkt (newpkt);
#endif
#if CLEANG_MODE == MESSAGE_LESS
      int* enbIP = rte_malloc( "int", sizeof (int), 0);
      if (enbIP == NULL) {
	printf ("cannot allocate enbIP\n");
      }
      // TODO: This should be changed to dynamic
      *enbIP = ENB1IP;
      //int code = rte_hash_add_key_data(encap_hash, &(c->ueIP), enbIP);
      int code = rte_hash_add_key_with_hash_data(encap_hash, &(tc8->ip), MY_HASH_FUNCTION(tc8->ip), enbIP);
      if (code) {
	critical_pprint ("Error in adding enbip, ueip to the hash\n");
	critical_print ("code is %d\n", code);
      }

#endif

#if CLEANG_EXTENDED_HASH == ACTIVATED
/*
#define CleanCoreStateActive 0
#define CleanCoreStatePause 1

struct cleanCoreState {
uint32_t state;
uint32_t ip;
uint32_t enbIP;
uint64_t imsi;
  };

*/

      struct cleanCoreState* ccs = rte_malloc( "struct cleanCoreState", sizeof (struct cleanCoreState), 0);
      if (ccs == NULL) {
	printf ("cannot allocate ccs\n");
      }
      // TODO: This should be changed to dynamic
      ccs->ip = tc8->ip;
      ccs->state = CleanCoreStateActive;
      ccs->enbIP = tc5->enbIP;
      ccs->imsi = tc8->imsi;
      //int code = rte_hash_add_key_data(encap_hash, &(c->ueIP), enbIP);
      int code2 = rte_hash_add_key_with_hash_data(core_hash, &(tc8->ip), MY_HASH_FUNCTION(tc8->ip), ccs);
      if (code2) {
	critical_pprint ("Error in adding enbip, ueip to the hash\n");
	critical_print ("code is %d\n", code2);
      }

#endif
      ali_debug_pprint ("tltec8 is being sent \n");
      return 0;
    }

    if (*rte_pktmbuf_mtod (pkt,char *) == HLTE2_MESSAGE_CODE_C)  
    {
      ali_debug_pprint ("hLTE2C received \n");
      struct hLTE2C *hc2 = (struct hLTE2C *) rte_pktmbuf_mtod (pkt,char *);
      uint32_t tempImsi = hc2->imsi;
      struct hLTE3C *hc3;
      //   users[tempImsi].state = ENB_STATE_HANDOVER;
      //     s1dltos1ul[users[tempImsi].s1dl] = l7->s1ul;
      //     ali_debug_pprint2 ("before changing the size\n");
      if (sizeof (struct hLTE3C) - sizeof (struct hLTE2C) > 0)
      {               // more space is needed in the packet
	rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct hLTE3C) - sizeof (struct hLTE2C)));
	ali_debug_pprint2 ("increasing the size\n");
      }
      else
      {               // the packet is already larger than it shold be
	rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct hLTE2C) - sizeof (struct hLTE3C)));
	ali_debug_pprint2 ("decreasing the size\n");
      }
      hc3 = (struct hLTE3C *) rte_pktmbuf_mtod (pkt,char *);
      ali_debug_pprint2 ("after setting are\n");
      hc3->messageCode = HLTE3_MESSAGE_CODE_C;
      ali_debug_pprint2 ("after first change in are\n");
      hc3->imsi = tempImsi;
      //snprintf (are->res, 256, "%s", "This is res!");
      prependIPHeader (pkt, EUC1IP, ENB2IP, IP_TYPE_NAS);
      prependETHF2toF3 (pkt);
      meta->destination = CLEANG_TOWARD_ENB;
      meta->action = ONVM_NF_ACTION_OUT;
      ali_debug_pprint ("hltec3 is being sent \n");
      return 0;
    }



    if (*rte_pktmbuf_mtod (pkt,char *) == HLTE4_MESSAGE_CODE_C)  
    {
      ali_debug_pprint ("hLTE4C received \n");
      struct hLTE4C *hc4 = (struct hLTE4C *) rte_pktmbuf_mtod (pkt,char *);
      uint32_t tempImsi = hc4->imsi;
      struct hLTE5C *hc5;
      //   users[tempImsi].state = ENB_STATE_HANDOVER;
      //     s1dltos1ul[users[tempImsi].s1dl] = l7->s1ul;
      //     ali_debug_pprint2 ("before changing the size\n");
      if (sizeof (struct hLTE5C) - sizeof (struct hLTE4C) > 0)
      {               // more space is needed in the packet
	rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct hLTE5C) - sizeof (struct hLTE4C)));
	ali_debug_pprint2 ("increasing the size\n");
      }
      else
      {               // the packet is already larger than it shold be
	rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct hLTE4C) - sizeof (struct hLTE5C)));
	ali_debug_pprint2 ("decreasing the size\n");
      }
      hc5 = (struct hLTE5C *) rte_pktmbuf_mtod (pkt,char *);
      ali_debug_pprint2 ("after setting are\n");
      hc5->messageCode = HLTE5_MESSAGE_CODE_C;
      ali_debug_pprint2 ("after first change in are\n");
      hc5->imsi = tempImsi;
      //snprintf (are->res, 256, "%s", "This is res!");
      prependIPHeader (pkt, EUC1IP, ENB1IP, IP_TYPE_NAS);
      prependETHF2toF3 (pkt);
      meta->destination = CLEANG_TOWARD_ENB;
      meta->action = ONVM_NF_ACTION_OUT;
      ali_debug_pprint ("hltec5 is being sent \n");
      return 0;
    }

    if (*rte_pktmbuf_mtod (pkt,char *) == ILTE5_MESSAGE_CODE_C)  
    {
      ali_debug_pprint ("iLTE5C received \n");
      struct iLTE5C *ic5 = (struct iLTE5C *) rte_pktmbuf_mtod (pkt,char *);
      uint32_t tempImsi = ic5->imsi;
      struct iLTE7C *ic7;
      //   users[tempImsi].state = ENB_STATE_HANDOVER;
      //     s1dltos1ul[users[tempImsi].s1dl] = l7->s1ul;
      //     ali_debug_pprint2 ("before changing the size\n");
      if (sizeof (struct iLTE7C) - sizeof (struct iLTE5C) > 0)
      {               // more space is needed in the packet
	rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct iLTE7C) - sizeof (struct iLTE5C)));
	ali_debug_pprint2 ("increasing the size\n");
      }
      else
      {               // the packet is already larger than it shold be
	rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct iLTE5C) - sizeof (struct iLTE7C)));
	ali_debug_pprint2 ("decreasing the size\n");
      }
      ic7 = (struct iLTE7C *) rte_pktmbuf_mtod (pkt,char *);
      ali_debug_pprint2 ("after setting are\n");
      ic7->messageCode = ILTE7_MESSAGE_CODE_C;
      ali_debug_pprint2 ("after first change in are\n");
      ic7->imsi = tempImsi;
      //snprintf (are->res, 256, "%s", "This is res!");
      prependIPHeader (pkt, EUC1IP, ENB1IP, IP_TYPE_NAS);
      prependETHF2toF3 (pkt);
      meta->destination = CLEANG_TOWARD_ENB;
      meta->action = ONVM_NF_ACTION_OUT;
      ali_debug_pprint ("iltec7 is being sent \n");
      return 0;
    }


    if (*rte_pktmbuf_mtod (pkt,char *) == ALTE1_MESSAGE_CODE_C)  
    {
      ali_debug_pprint ("aLTE1C received \n");
      struct aLTE1C *ac1 = (struct aLTE1C *) rte_pktmbuf_mtod (pkt,char *);
      uint32_t tempImsi = ac1->imsi;
      struct aLTE2C *ac2;
      //   users[tempImsi].state = ENB_STATE_HANDOVER;
      //     s1dltos1ul[users[tempImsi].s1dl] = l7->s1ul;
      //     ali_debug_pprint2 ("before changing the size\n");
      if (sizeof (struct aLTE2C) - sizeof (struct aLTE1C) > 0)
      {               // more space is needed in the packet
	rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct aLTE2C) - sizeof (struct aLTE1C)));
	ali_debug_pprint2 ("increasing the size\n");
      }
      else
      {               // the packet is already larger than it shold be
	rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct aLTE1C) - sizeof (struct aLTE2C)));
	ali_debug_pprint2 ("decreasing the size\n");
      }
      ac2 = (struct aLTE2C *) rte_pktmbuf_mtod (pkt,char *);
      ali_debug_pprint2 ("after setting are\n");
      ac2->messageCode = ALTE2_MESSAGE_CODE_C;
      ali_debug_pprint2 ("after first change in are\n");
      ac2->imsi = tempImsi;
      //snprintf (are->res, 256, "%s", "This is res!");
      prependIPHeader (pkt, EUC1IP, ENB1IP, IP_TYPE_NAS);
      prependETHF2toF3 (pkt);
      meta->destination = CLEANG_TOWARD_ENB;
      meta->action = ONVM_NF_ACTION_OUT;
      ali_debug_pprint ("altec2 is being sent \n");
      return 0;
    }

    if (*rte_pktmbuf_mtod (pkt,char *) == DLTE2_MESSAGE_CODE_C)  
    {
      ali_debug_pprint ("dLTE2C received \n");
      struct dLTE2C *dc2 = (struct dLTE2C *) rte_pktmbuf_mtod (pkt,char *);
      uint32_t tempImsi = dc2->imsi;
      struct dLTE5C *dc5;
      //   users[tempImsi].state = ENB_STATE_HANDOVER;
      //     s1dltos1ul[users[tempImsi].s1dl] = l7->s1ul;
      //     ali_debug_pprint2 ("before changing the size\n");
      if (sizeof (struct dLTE5C) - sizeof (struct dLTE2C) > 0)
      {               // more space is needed in the packet
	rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct dLTE5C) - sizeof (struct dLTE2C)));
	ali_debug_pprint2 ("increasing the size\n");
      }
      else
      {               // the packet is already larger than it shold be
	rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct dLTE2C) - sizeof (struct dLTE5C)));
	ali_debug_pprint2 ("decreasing the size\n");
      }
      dc5 = (struct dLTE5C *) rte_pktmbuf_mtod (pkt,char *);
      ali_debug_pprint2 ("after setting are\n");
      dc5->messageCode = DLTE5_MESSAGE_CODE_C;
      ali_debug_pprint2 ("after first change in are\n");
      dc5->imsi = tempImsi;
      //snprintf (are->res, 256, "%s", "This is res!");
      prependIPHeader (pkt, EUC1IP, ENB1IP, IP_TYPE_NAS);
      prependETHF2toF3 (pkt);
      meta->destination = CLEANG_TOWARD_ENB;
      meta->action = ONVM_NF_ACTION_OUT;
      ali_debug_pprint ("dlte5c is being sent \n");
      return 0;
    }


    if (*rte_pktmbuf_mtod (pkt,char *) == HLTE7_MESSAGE_CODE_C)  
    {
      ali_debug_pprint ("HLTE7C is received \n");
      struct hLTE7C *h7c = (struct hLTE7C *) rte_pktmbuf_mtod (pkt,char *);
      uint32_t tempImsi = h7c->imsi;
      struct hLTE11C *h11c;
      //users[tempImsi].state = ENB_STATE_HANDOVER;
      //s1dltos1ul[users[tempImsi].s1dl] = l7->s1ul;
      ali_debug_pprint2 ("before changing the size\n");
      if (sizeof (struct hLTE11C) - sizeof (struct hLTE7C) > 0)
      {               // more space is needed in the packet
	rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct hLTE11C) - sizeof (struct hLTE7C)));
	ali_debug_pprint2 ("increasing the size\n");
      }
      else
      {               // the packet is already larger than it shold be
	rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct hLTE7C) - sizeof (struct hLTE11C)));
	ali_debug_pprint2 ("decreasing the size\n");
      }
      h11c = (struct hLTE11C *) rte_pktmbuf_mtod (pkt,char *);
      ali_debug_pprint2 ("after setting are\n");
      h11c->messageCode = HLTE11_MESSAGE_CODE_C;
      ali_debug_pprint2 ("after first change in are\n");
      h11c->imsi = tempImsi;
      //snprintf (are->res, 256, "%s", "This is res!");
      prependIPHeader (pkt, EUC1IP, ENB1IP, IP_TYPE_NAS);
      prependETHF2toF3 (pkt);
      meta->destination = CLEANG_TOWARD_ENB;
      meta->action = ONVM_NF_ACTION_OUT;
      //TODO: probably need to send a psudo message back to calculate the timing.
      ali_debug_pprint ("virtual hlte11 is being send back to enb1!\n");
      return 0;
    }



    // d8
    if (*rte_pktmbuf_mtod (pkt,char *) == DLTE5_MESSAGE_CODE_C)  
    {
      ali_debug_pprint ("DLTE5C received \n");
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
      meta->destination = CLEANG_TOWARD_ENB;*/
      meta->action = ONVM_NF_ACTION_DROP;
      ali_debug_pprint ("dlte5C is being dropped\n");
      return 0;
    }

    if (*rte_pktmbuf_mtod (pkt,char *) == ALTE2_MESSAGE_CODE_C)  
    {
      ali_debug_pprint ("ALTE2C received \n");
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
      meta->destination = CLEANG_TOWARD_ENB;*/
      meta->action = ONVM_NF_ACTION_DROP;
      ali_debug_pprint ("alte2C is being dropped\n");
      return 0;
    }


    if (*rte_pktmbuf_mtod (pkt,char *) == ILTE7_MESSAGE_CODE_C)  
    {
      ali_debug_pprint ("IaLTE7C received \n");
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
      meta->destination = CLEANG_TOWARD_ENB;*/
      meta->action = ONVM_NF_ACTION_DROP;
      ali_debug_pprint ("ilte7C is being dropped\n");
      return 0;
    }
  }

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

  if ((arg_offset = onvm_nflib_init (argc, argv, NF_TAG,&nf_info )) < 0)
    return -1;
  argc -= arg_offset;
  argv += arg_offset;
  destination = nf_info->service_id + 1;

  if (parse_app_args (argc, argv, progname) < 0)
    rte_exit (EXIT_FAILURE, "Invalid command-line arguments\n");
  //AliMamad
  myState.noOfCores = 1;
  myState.coreIPAddresses[0] = IP_10_0_0_0 + 3;
#if COMPLETE_T_LOGGING == ACTIVATED
  int w;
  for (w=0; w < COMPLETE_MAX_NUMBER_OF_MESSAGE_CODE;w++)
  {
    ctl[w] = (struct timespec*) calloc (USER_STATE_SIZE, sizeof (struct timespec));
  }
#endif

#if CLEANG_MODE == MESSAGE_LESS
  encap_hash = rte_hash_find_existing("CoreDataPathHash");
  if (encap_hash == NULL) {
    rte_panic("Failed to find hash table, errno = %d\n",
	rte_errno);
  }
#endif
#if CLEANG_EXTENDED_HASH == ACTIVATED
  ali_debug_pprint("before setting hash parametres\n");
  struct rte_hash_parameters encap_hash_params = {
    .name = "CoreControlHash",
    //.entries = 40000000,
    //For 10M users we need a large huge page, 16384 pages of 2MB works
    //even 8k works but other NFs also need some memory space
    .entries = NO_OF_HASH_ENTRIES_IN_CORE_FORWARDER,
    .key_len = sizeof(uint32_t),
    .hash_func = DEFAULT_HASH_FUNC,
    .hash_func_init_val = 0,
    .socket_id = rte_socket_id(),
  };
  ali_debug_pprint("after setting hash parameteres, before creating hash\n");
  core_hash = rte_hash_create(&encap_hash_params);
  if (core_hash == NULL) {
    critical_pprint("unable to make the hash!!\n");
    rte_panic("Failed to create cdev_map hash table, errno = %d\n",
	rte_errno);
  }
  ali_debug_pprint("hash created successfully\n");
#endif

  onvm_nflib_run (nf_info, &packet_handler);
#if COMPLETE_T_LOGGING == ACTIVATED
  printf ("writing complete log time to file\n");
  writeCompleteTimeLogToFile("cf3core.txt", ctl);
#endif
  /*  FILE *f = fopen("output.txt", "w");
      if (f == NULL)
      {
      printf("Error opening file!\n");
      exit(1);
      }
      int j;
      for (j=0; j < USER_STATE_SIZE; j++)
      {
      fprintf(f, "userID %d, startnano %ld endnano %ld startsec %ld endsec %ld\n", j, startTimes[j].tv_nsec, endTimes[j].tv_nsec, startTimes[j].tv_sec, endTimes[j].tv_sec);
      }
      fclose(f);
   */
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
pmeta->destination = CLEANG_TOWARD_ENB;
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
