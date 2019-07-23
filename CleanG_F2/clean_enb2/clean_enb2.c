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
static struct timespec* startTimes;
static struct timespec* endTimes;
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
packet_handler (struct rte_mbuf *pkt, struct onvm_pkt_meta *meta, __attribute__((unused)) struct onvm_nf_info *nf_infu)
{
  //ali_debug_print("debugtest %i", 11);
  //printf("%i",ALIDEBUG);
  static uint32_t counter = 0;
  if (++counter == print_delay && SHOW_PACKET_STATS != DISABLED)
    {
      do_stats_display (pkt);
      counter = 0;
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
      ali_debug_print2 ("userID is : %i\n", sm->userID);
      int tempUserID = sm->userID;
      //clock_gettime(CLOCK_REALTIME, &startTimes[tempUserID]);
           //printf ("check 1\n");
      if (sm->command == NEW_USER_COMMAND){
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
      meta->action = ONVM_NF_ACTION_OUT;
      //printf ("check 4\n");
      }
      if (sm->command == HANDOVER_COMMAND){
        struct  hLTE2C *h2c;
        ali_debug_pprint("handover command received\n");
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
      prependIPHeader (pkt, ENB1IP, myState.coreIPAddresses[0], IP_TYPE_NAS);
      prependETHF2toF3 (pkt);
      ali_debug_pprint ("Handover message is being sent!\n");
      //send directly to port
      //printf ("check 3\n");
      struct onvm_pkt_meta *pmeta;
      pmeta = onvm_get_pkt_meta (pkt);
      pmeta->destination = 0;
      pmeta->action = ONVM_NF_ACTION_OUT;
      //printf ("check 4\n");
      }
      // detach commmand
      if (sm->command == DETACH_COMMAND){
        struct  dLTE2C *d2c;
        ali_debug_pprint("detach command received\n");
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
      pmeta->action = ONVM_NF_ACTION_OUT;
      //printf ("check 4\n");
      }
      // idle to active command
      if (sm->command == IDLE_TO_ACTIVE_COMMAND){
        struct  iLTE5C *i5c;
        ali_debug_pprint("idle to active command received\n");
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
      pmeta->action = ONVM_NF_ACTION_OUT;
      //printf ("check 4\n");
      }
      // active to idle command
      if (sm->command == ACTIVE_TO_IDLE_COMMAND){
        struct  aLTE1C *a1;
        ali_debug_pprint("active to idle command received\n");
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
      pmeta->action = ONVM_NF_ACTION_OUT;
      //printf ("check 4\n");
      }

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
	  rte_pktmbuf_adj (pkt, sizeof (struct GTPUHeader));
	  //pkt->port = 11;
          meta->destination = LTE_DATA_SERVICE_ID;
	  meta->action = ONVM_NF_ACTION_TONF;
	  return 0;
	}

      if (iph->next_proto_id == IP_TYPE_NAS)
	{
	  ali_debug_pprint ("a nas message is received\n");
	  // remove the ip header
	  rte_pktmbuf_adj (pkt, 20);
	  if (*rte_pktmbuf_mtod (pkt,char *) == TLTE8_MESSAGE_CODE_C)  
            {
              ali_debug_pprint ("TLTE8C received \n");
              //struct tLTE8C *l8 = (struct tLTE8C *) rte_pktmbuf_mtod (pkt,char *);
              //uint32_t tempImsi = l8->imsi;
              //struct tLTE8C *l8;
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
              meta->action = ONVM_NF_ACTION_OUT;
              ali_debug_pprint ("hlte7 is being sent to Core\n");
              return 0;
            }
	    // this is the extra message handled in enb 2
            if (*rte_pktmbuf_mtod (pkt,char *) == HLTE3_MESSAGE_CODE_C)  
            {
              ali_debug_pprint ("HLTE3C is received \n");
              struct hLTE3C *h3c = (struct hLTE3C *) rte_pktmbuf_mtod (pkt,char *);
              uint32_t tempImsi = h3c->imsi;
              struct hLTE4C *h4c;
	      //users[tempImsi].state = ENB_STATE_HANDOVER;
	      //s1dltos1ul[users[tempImsi].s1dl] = l7->s1ul;
              ali_debug_pprint2 ("before changing the size\n");
              if (sizeof (struct hLTE4C) - sizeof (struct hLTE3C) > 0)
                {               // more space is needed in the packet
                  rte_pktmbuf_append (pkt, (uint16_t) (sizeof (struct hLTE4C) - sizeof (struct hLTE3C)));
                  ali_debug_pprint2 ("increasing the size\n");
                }
              else
                {               // the packet is already larger than it shold be
                  rte_pktmbuf_adj (pkt, (uint16_t) (sizeof (struct hLTE3C) - sizeof (struct hLTE4C)));
                  ali_debug_pprint2 ("decreasing the size\n");
                }
              h4c = (struct hLTE4C *) rte_pktmbuf_mtod (pkt,char *);
              ali_debug_pprint2 ("after setting are\n");
              h4c->messageCode = HLTE4_MESSAGE_CODE_C;
              ali_debug_pprint2 ("after first change in are\n");
              h4c->imsi = tempImsi;
              //snprintf (are->res, 256, "%s", "This is res!");
              prependIPHeader (pkt, ENB2IP, EUC1IP, IP_TYPE_NAS);
              prependETHF2toF3 (pkt);
              meta->destination = 0;
              meta->action = ONVM_NF_ACTION_OUT;
              ali_debug_pprint ("hlte4 is being sent to Core\n");
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
              meta->destination = 0;*/
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
              meta->destination = 0;*/
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
              meta->destination = 0;*/
              meta->action = ONVM_NF_ACTION_DROP;
              ali_debug_pprint ("ilte7C is being dropped\n");
              return 0;
            }
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

  startTimes = calloc (USER_STATE_SIZE, sizeof(struct timespec));
  endTimes = calloc (USER_STATE_SIZE, sizeof(struct timespec));

  onvm_nflib_run (nf_info, &packet_handler);
  FILE *f = fopen("output.txt", "w");
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
