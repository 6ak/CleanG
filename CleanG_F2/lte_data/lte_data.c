/*********************************************************************
 *                     openNetVM
 *       https://github.com/sdnfv/openNetVM
 *
 *  Copyright 2015 George Washington University
 *            2015 University of California Riverside
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 G *  you may not use this file except in compliance with the License.
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
#include <math.h>
#include <time.h>

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_hash.h>

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

#if DATA_DELAY_LOGGING == ACTIVATED
  long long recorded_delays [RECORDED_DELAY_SIZE];
  static int recorded_delay_counter = 0;  
#endif


/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;
static uint32_t maximum_observed_userID = NUMBER_OF_USERS;

static struct rte_hash *data_gen_hash;

/* number of package between each print */
static uint32_t print_delay = 1000000;
//static struct timespec endTimes[USER_STATE_SIZE];
//static uint32_t noOfReceivedData[USER_STATE_SIZE];
//static uint32_t ipToUserID[USER_STATE_SIZE];
static struct dataGeneratorState userStates[USER_STATE_SIZE];
static uint32_t numberOfConnectedUsers = 0;
static uint32_t destination;

struct rte_mempool *pktmbuf_pool;
// JUST TO SHOW HIGH DELAY WARNING ONCE
#if CRITICALPRINT == ENABLED
static uint32_t highDelayDataPacketFlag = 0;
#endif
/*
 * Print a usage message
 */
  static void
usage (const char *progname)
{
  critical_print ("Usage: %s [EAL args] -- [NF_LIB args] -- -d <destination> -p <print_delay>\n\n", progname);
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
  critical_print ("%s%s", clr, topLeft);

  critical_pprint ("PACKETS\n");
  critical_pprint ("-----\n");
  critical_print ("Port : %d\n", pkt->port);
  critical_print ("Size : %d\n", pkt->pkt_len);
  critical_print ("N°   : %d\n", pkt_process);
  critical_pprint ("\n\n");

  ip = onvm_pkt_ipv4_hdr (pkt);
  if (ip != NULL)
  {
    onvm_pkt_print (pkt);
  }
  else
  {
    critical_pprint ("No IP4 header found\n");
  }
}

  static int
packet_handler (struct rte_mbuf *pkt, struct onvm_pkt_meta *meta, __attribute__((unused)) struct onvm_nf_info *nf_info)
{
  //ali_debug_print("debugtest %i", 11);
  //critical_print("%i",ALIDEBUG);
  static uint32_t counter = 0;
  //static uint32_t dataCounter = 0;
  if (++counter == print_delay && SHOW_PACKET_STATS != DISABLED)
  {
    do_stats_display (pkt);
    counter = 0;
  }
  if (pkt->port != DATA_COMMAND_PORT) {
    //printf ("data pkt\n");
    //    struct ipv4_hdr *iph;
    //    iph = (struct ipv4_hdr *) (rte_pktmbuf_mtod (pkt,char *));
    //usleep (10000000);
    //critical_print ("HAVIJ REP1IP %d\n", REP1IP);
    //critical_print ("HAVIJ source ip %lu\n", (unsigned long )rte_be_to_cpu_32(iph->src_addr));
    /*    if (rte_be_to_cpu_32 (iph->src_addr) == REP1IP)
	  {
    //      uint32_t tempDestIP = rte_be_to_cpu_32 (iph->dst_addr) - IP_192_168_1_1;
    //      noOfReceivedData[ipToUserID[tempDestIP]]++;
    if (noOfReceivedData[ipToUserID[tempDestIP]] == SENT_PACKET_NO * REPLIED_PER_PACKET)
    {
    //critical_print("all data packets are received for %u \n", tempDestIP);
    clock_gettime (CLOCK_REALTIME, &endTimes[ipToUserID[tempDestIP]]);
    }
    else if (noOfReceivedData[ipToUserID[tempDestIP]] > SENT_PACKET_NO * REPLIED_PER_PACKET)
    {
    //TODO: following line is not practical anymore!
    //critical_pprint ("Error! number of recieved packets larger than expected!!\n");
    }
    dataCounter++;*/
#if PRINT_DATA_NUMBER_OF_ACTIVE_USERS == ACTIVATED
    if (counter % 100000 == 1) {
      printf ("Number of active users is: %u\n", numberOfConnectedUsers);
    }
#endif
#if DATA_DELAY_LOGGING == ACTIVATED
    //printf ("packt length is %u\n",rte_pktmbuf_data_len(pkt));
    rte_pktmbuf_adj(pkt, sizeof ( struct ipv4_hdr));
    struct timespec* ts = rte_pktmbuf_mtod(pkt, struct timespec*);
    //printf ("sec %ld\n", ts->tv_sec);
    //printf ("nsec %ld\n", ts->tv_nsec);
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    //printf ("delay is %ld\n", returnNanoDifference (*ts, now));
    recorded_delays[recorded_delay_counter] = returnNanoDifference (*ts, now);
    recorded_delay_counter++;
    if (recorded_delay_counter == RECORDED_DELAY_SIZE) {
      recorded_delay_counter = 0;
      //printf ("delay counter reset!\n");
    }
#endif
    ali_debug_pprint ("getting packes back from replier\n");
    meta->action = ONVM_NF_ACTION_DROP;
    meta->destination = 0;
    /* if (dataCounter == 18000)
       {
       struct timespec tsp;
       clock_gettime (CLOCK_REALTIME, &tsp);
       critical_pprint ("nano: %ld\n", tsp.tv_nsec);
       critical_pprint ("second: %ld\n", tsp.tv_sec);
       }*/
    //      printf ("end of data pkt\n");
    return 0;
    //  }
  }
  if (pkt->port == DATA_COMMAND_PORT)
  {
    ali_debug_pprint ("a data command with type received \n");
    struct sendDataCommand *sdc;
    //printf ("packet command received\n");
    sdc = (struct sendDataCommand *) (rte_pktmbuf_mtod (pkt,char *));
    //printf ("its type is %d\n", sdc->commandCode);
    ali_debug_print ("packet port is %i\n", pkt->port);
    if (sdc->commandCode == SEND_DATA_COMMAND) {
      numberOfConnectedUsers++;
      //critical_print ("WOOOW! sending data to %u\n", sdc->imsi);
      uint32_t tempip;
      tempip = sdc->ip;
      //ipToUserID[sdc->ip - IP_192_168_1_1] = sdc->imsi;
      ali_debug_print ("start sending data for %lu\n", (unsigned long) tempip);
      //printf("before lookup\n");
      if (sdc->imsi > maximum_observed_userID) {
	maximum_observed_userID = sdc->imsi;
      }
      int32_t lookup_val = rte_hash_lookup(data_gen_hash, &(sdc->imsi));
      if (lookup_val == -EINVAL) {
	critical_pprint ("invalid parameters for hash lookup\n");
      } else if ( lookup_val < 0 ) {
	rte_hash_add_key( data_gen_hash, &(sdc->imsi));
	if (sdc->imsi >= NUMBER_OF_USERS) {
	  printf ("really something bad happened!\n");
	}
	userStates[sdc->imsi].ip = sdc->ip;
	clock_gettime(CLOCK_REALTIME, &(userStates[sdc->imsi].lastSentDataPacket));
	userStates[sdc->imsi].active = ACTIVE;
	ali_debug_print ("god the data command for %lu and user state is %d\n", sdc->imsi, userStates[sdc->imsi].active);
	// Instead of current time we can use a small time, so for sure we see a packet is sent in first round, because probably user had something to send and he became active
	// TODO: this rate can be dynamic and different for each user.
	userStates[sdc->imsi].ratePerSecond = DEFAULT_USER_RATE;
	//printf("end of attach command\n");
      }
    } else if (sdc->commandCode == STOP_DATA_COMMAND) {
      numberOfConnectedUsers--;
      //printf ("before stop\n");
      ali_debug_print ("start stopping data for %lu\n", sdc->imsi);
      int delState = rte_hash_del_key(data_gen_hash, &(sdc->imsi));
      if (delState < 0) {
	critical_pprint ("something is wrong with deletion of hash entry!\n");
	critical_print ("code is %d\n",delState);
	if (delState == -ENOENT) {
	  critical_pprint ("no entry!\n");
	}
	if (delState == -EINVAL) {
	  critical_pprint ("inval param!\n");
	}
	critical_print ("imsi of user is %lu\n",sdc->imsi);
      } else {
	ali_debug_pprint_user(sdc->imsi,"deletion with no problem\n");
      }
      if (sdc->imsi >= NUMBER_OF_USERS) {
	printf ("really something bad happened!\n");
      }

      userStates[sdc->imsi].active = INACTIVE;
      //printf ("end of handling stop\n");
    }
    else if (sdc->commandCode == RESUME_DATA_COMMAND) {
      numberOfConnectedUsers++;
      if (sdc->imsi >= NUMBER_OF_USERS) {
	printf ("really something bad happened!\n");
      }
      //printf ("before resume\n");
      ali_debug_print ("resume sending data for %lu\n", sdc->imsi);
      int32_t lookup_val = rte_hash_lookup(data_gen_hash, &(sdc->imsi));
      if (lookup_val == -EINVAL) {
	critical_pprint ("invalid parameters for hash lookup\n");
      } else if ( lookup_val < 0 ) {
	rte_hash_add_key( data_gen_hash, &(sdc->imsi));
	//userStates[sdc->imsi].ip = sdc->ip;
	clock_gettime(CLOCK_REALTIME, &(userStates[sdc->imsi].lastSentDataPacket));
	userStates[sdc->imsi].active = ACTIVE;
	ali_debug_print ("god the data RESUME command for %lu and user state is %d\n", sdc->imsi, userStates[sdc->imsi].active);
	// Instead of current time we can use a small time, so for sure we see a packet is sent in first round, because probably user had something to send and he became active
	// TODO: this rate can be dynamic and different for each user.
	//userStates[sdc->imsi].ratePerSecond = DEFAULT_USER_RATE;
      }
      //printf ("after resume\n");
    } else { 
      critical_pprint ("unknown data command code!!\n");
    }
    meta->action = ONVM_NF_ACTION_DROP;
    //printf ("end of handling packet!\n");
    return 0;
  }

  // unhandled pacekt
  critical_pprint ("We should never get here, unhandled packet\n");
  //meta->action = ONVM_NF_ACTION_TONF;
  meta->action = ONVM_NF_ACTION_DROP;
  meta->destination = destination;
  //printf("end of handling packet \n");
  return 0;
}


inline static void sendNPacketForUser (uint32_t userID, uint32_t noOfDataPackets) {
  //SENDING packets starts here
  struct rte_mbuf *pkts[noOfDataPackets];
  uint32_t i;
  ali_debug_print ("sending %u packet for %u user\n", noOfDataPackets, userID);

  //doing bulk alloc in hope of getting better performance
  //rte_pktmbuf_alloc_bulk (pktmbuf_pool, pkts, noOfDataPackets);
  //it was worse than single packet!

  //critical_print ("Creating %d packets to send to %d\n", NUM_PKTS, destination);
  for (i = 0; i < noOfDataPackets; i++)
  {
    ali_debug_print2 ("Start sending packet: %d\n", i);
    struct onvm_pkt_meta *pmeta;
    ali_debug_pprint2("before alloc\n");
    pkts[i] = rte_pktmbuf_alloc (pktmbuf_pool);
#if CRITICALPRINT == ENABLED
    if (pkts[i] == NULL) {
      critical_pprint ("did not manage to allocate memory for the packet \n");
      printf ("did not manage to allocate memory for the packet \n");
      return;
    }
    ali_debug_pprint2("after alloc\n");
#endif
    //Add IP header
    prependIPHeader (pkts[i], userStates[userID].ip, REP1IP, 0);	//is it a right next proto?
#if CRITICALPRINT == ENABLED
    if (userStates[userID].ip < IP_192_168_1_1) {
      //printf ("INCORRECT IP!!!!! %u minimum %lu \n ", userStates[userID].ip, IP_192_168_1_1);
      continue;
      //exit (1);
    }
#endif
#if DATA_DELAY_LOGGING == ACTIVATED
    struct timespec currentTime;
    clock_gettime(CLOCK_REALTIME, &currentTime);
    struct timespec* ts = (struct timespec* ) rte_pktmbuf_append (pkts[i], sizeof (struct timespec));
    memcpy (ts, &currentTime, sizeof (struct timespec));
#endif
    pmeta = onvm_get_pkt_meta (pkts[i]);  
    if (SIMULATION_MODE != CLEAN_G) {
      pmeta->destination = LTE_ENB1_SERVICE_ID;
      pmeta->action = ONVM_NF_ACTION_TONF;
      pkts[i]->port = DATA_PACKET_PORT;
      //pkts[i]->hash.rss = i;
    } else {
      pmeta->destination = 0;
#if CLEANG_MULTIPORT == ACTIVATED
          pmeta->destination = userID % 3;
#endif
      pmeta->action = ONVM_NF_ACTION_OUT;
      ali_debug_pprint ("before ip\n");
      prependIPHeader (pkts[i], ENB1IP, EUC1IP, IP_TYPE_GUSER);
      ali_debug_pprint ("before ethernet\n");
      prependETHF2toF3 (pkts[i]);
      ali_debug_pprint ("data message is being forwarded!\n");
//      printf ("data packet size is %d\n",rte_pktmbuf_data_len(pkts[i]));
    }
    //int j,k;
    //j = scanf("%i",&k);
    //critical_print("go to next packet %i",j*k);
    //sleep (.2);
    //printf ("data packet size is %u \n", pkts[i]->pkt_len);
    onvm_nflib_return_pkt (nf_info,pkts[i]);
  }
}


static int data_packet_sender(void *ptr) {
  struct DataSenderSpecifier* ds = (struct DataSenderSpecifier*) ptr;
  
 //(void) ptr;
  srand(time(NULL));
  float randomFloat = (float) rand() / (float) RAND_MAX;
  critical_pprint ("before whilewow!\n");
  //int numberOfSendPackets = 0;
  int whileCounter = 0;
  while (1) {
    //printf ("thread %i went to next while\n", ds->selectedShard);
    uint32_t i;
    whileCounter++;
    //critical_print ("in while %d\n", whileCounter);
    struct timespec now;
    //critical_print ("in while, user 0 state is %d\n", userStates[0].active);
    //critical_pprint ("noop\n");

    clock_gettime(CLOCK_REALTIME, &now);
    for (i=ds->selectedShard; i <= maximum_observed_userID; i += TOTAL_NUMBER_OF_DATA_CENTER_ENGINES) {
      //  critical_print ("i is %d\n", i);
      //if ( rte_hash_lookup(data_gen_hash, &i) >= 0) {
	//TODO: changed the hash lookup to state active in the hope of making it faster

	if (userStates[i].active == ACTIVE) {
	//critical_pprint("in if\n");
	//      critical_print ("in if i is %d\n", i);
#if CRITICALPRINT == ENABLED
	if (userStates[i].active != ACTIVE) {
	  // TODO: the severtiy of following message is reduced for now to ali_debug
	  ali_debug_pprint_user(i,"Something is wrong! user is in hash but its state is not active!\n");
	}
#endif
	//printf ("before clock\n");
	if (i % CLOCK_READ_REDUCER < TOTAL_NUMBER_OF_DATA_CENTER_ENGINES) {
	  clock_gettime(CLOCK_REALTIME, &now);
	  //randomFloat = (float) rand() / (float) RAND_MAX;
	}
	//printf("after clock\n");
	//removed random making from here, so to skip make random number all the time

	randomFloat = (float) rand() / (float) RAND_MAX;
	long long timeDiff = llreturnNanoDifference (userStates[i].lastSentDataPacket, now);
#if CRITICALPRINT == ENABLED
	if (timeDiff > MAXIMUM_DELAY_BETWEEN_SAME_USER_PACKETS && highDelayDataPacketFlag != 1) {
	  printf ("WARNING!!! Data Generator is over maximum capacity!!\n");
	  highDelayDataPacketFlag = 1;
	}
#endif
	userStates[i].lastSentDataPacket = now;
	//float packetSendingChance = 1.0 - exp (-1 * DEFAULT_USER_RATE * (1.0 * timeDiff / 1000000000));
	//	critical_print ("time diff is %lld and divivded time diff is %ld \n", timeDiff, (long) timeDiff / 1000000000);
	double noOfPacketsToSend = DEFAULT_USER_RATE * 1.0 * timeDiff / 1000000000;
	//critical_print ("no of packet to send %e\n", noOfPacketsToSend);
	uint32_t intNoOpPacketsToSend = (int) noOfPacketsToSend;
	//	critical_print ("int no of packets to send %u\n", intNoOpPacketsToSend);
	double packetSendingChance = noOfPacketsToSend - intNoOpPacketsToSend;
	//critical_print ("packet sending chance %f\n",packetSendingChance);
	if (randomFloat < packetSendingChance) {
	  intNoOpPacketsToSend++;
	}
	/*uint32_t packetSendingLoopCounter = 0;
	  for (packetSendingLoopCounter = 0; packetSendingLoopCounter < intNoOpPacketsToSend; packetSendingLoopCounter++) {
	  ali_debug_print("no of sent packet! %d", ++numberOfSendPackets);
	  ali_debug_pprint ("lets send a data packet!\n");
	  ali_debug_print("time spent in nano second %lld\n",timeDiff);
	//ali_debug_print("sending chance is %f\n", packetSendingChance);
	//ali_debug_print("rand max is %d", RAND_MAX);
	}*/
	//printf ("before send, no of packet to send %u\n", intNoOpPacketsToSend);
	if (intNoOpPacketsToSend > 0) {
	  sendNPacketForUser(i, intNoOpPacketsToSend);
	}
	//printf ("after send\n");
      }
    }


    //critical_pprint("We are in data packet sender\n");
    //sleep(10);
  }
  critical_pprint("after while\n");
  return 0; 
}


  int
main (int argc, char *argv[])
{
  int arg_offset;
  const char *progname = argv[0];
  critical_pprint ("Ali dont forget you have added random cores to ali file!!!\n");
  if ((arg_offset = onvm_nflib_init (argc, argv, NF_TAG, &nf_info)) < 0)
    return -1;
  argc -= arg_offset;
  argv += arg_offset;
  destination = nf_info->service_id + 1;

  if (parse_app_args (argc, argv, progname) < 0)
    rte_exit (EXIT_FAILURE, "Invalid command-line arguments\n");
  int i;
  for (i=0; i< USER_STATE_SIZE; i++) {
    userStates[i].active = INACTIVE;
    userStates[i].ip = IP_192_168_1_1 - 1;
    userStates[i].ratePerSecond = 1;
    userStates[i].totalSentPacket = 0;
    clock_gettime(CLOCK_REALTIME, &(userStates[i].lastSentDataPacket));
  }
  ali_debug_pprint("before setting hash parametres\n");
  int number_of_hash_entries = 1024;
  if (NUMBER_OF_USERS > 1024) {
    number_of_hash_entries = NUMBER_OF_USERS;
  }
  struct rte_hash_parameters data_gen_hash_params = {
    .name = "DataGenHash",
    .entries = number_of_hash_entries,
    .key_len = sizeof(uint32_t),
    .hash_func = DEFAULT_HASH_FUNC,
    .hash_func_init_val = 0,
    .socket_id = rte_socket_id(),
  };
  ali_debug_pprint("after setting hash parameteres, before creating hash\n");
  data_gen_hash = rte_hash_create(&data_gen_hash_params);
  ali_debug_pprint("after hash create\n");
  if (data_gen_hash == NULL) {
    critical_pprint("unable to make the hash!!\n");
  }
  ali_debug_pprint("hash created successfully\n");

  printf ("getting the pool address\n");
  pktmbuf_pool = rte_mempool_lookup (PKTMBUF_POOL_NAME);
  if (pktmbuf_pool == NULL)
  {
    rte_exit (EXIT_FAILURE, "Cannot find mbuf pool!\n");
  }
  printf ("done with gettign the pool address\n");
  unsigned data_core = 0;
  //unsigned data_core1=0, data_core2=0, data_core3 = 0;
  data_core = rte_lcore_id();
  //printf ("main thread core is %u\n", main_core);
  //data_core1 = rte_get_next_lcore(main_core, 1,1);
  ///printf ("frist data core is %d\n", data_core1);
  //data_core2 = rte_get_next_lcore(data_core1, 1,1);
  //printf ("second data core is %d\n", data_core2);
  //data_core3 = rte_get_next_lcore(data_core2, 1,1);
  //printf ("third data core is %d\n", data_core3);
/*

#define TOTAL_NUMBER_OF_DATA_CENTER_ENGINES 3
struct DataSenderSpecifier {
    int totalNumberOfShards;
      int selectedShard;
}

*/

  //struct DataSenderSpecifier* ds1,*ds2,*ds3;
  struct DataSenderSpecifier* dataSenders[DATA_SENDER_CORE_NUMBER];
  int dsCounter = 1;
  for (dsCounter = 1; dsCounter <= DATA_SENDER_CORE_NUMBER; dsCounter++) {
    printf ("start using core %u\n", data_core);
    data_core = rte_get_next_lcore(data_core, 1,1);
    dataSenders[dsCounter-1] = (struct DataSenderSpecifier *)malloc(sizeof(struct DataSenderSpecifier));
    dataSenders[dsCounter-1]->totalNumberOfShards = TOTAL_NUMBER_OF_DATA_CENTER_ENGINES;
    dataSenders[dsCounter-1]->selectedShard = dsCounter - 1;
    rte_eal_remote_launch( data_packet_sender, (void*) dataSenders[dsCounter-1], data_core);
  }
    printf ("start using core %u\n", data_core);

  //ds1 = (struct DataSenderSpecifier *)malloc(sizeof(struct DataSenderSpecifier));
  //ds2 = (struct DataSenderSpecifier *)malloc(sizeof(struct DataSenderSpecifier));
  //ds3 = (struct DataSenderSpecifier *)malloc(sizeof(struct DataSenderSpecifier));
  
  ///ds1->totalNumberOfShards = TOTAL_NUMBER_OF_DATA_CENTER_ENGINES;
  //ds2->totalNumberOfShards = TOTAL_NUMBER_OF_DATA_CENTER_ENGINES;
  //ds3->totalNumberOfShards = TOTAL_NUMBER_OF_DATA_CENTER_ENGINES;

  //ds1->selectedShard = 0;
  //ds2->selectedShard = 1;
  //ds3->selectedShard = 2;


  //printf ("packet sender core is %u\n", data_core);
  //rte_eal_remote_launch( data_packet_sender, (void*)ds1, data_core1);
  //rte_eal_remote_launch( data_packet_sender, (void*)ds2, data_core2);
  //rte_eal_remote_launch( data_packet_sender, (void*)ds3, data_core3);


  onvm_nflib_run (nf_info, &packet_handler);




#if DATA_DELAY_LOGGING == ACTIVATED
  FILE *f = fopen ("output.txt", "w");
  if (f == NULL)
  {
    critical_pprint ("Error opening file!\n");
    exit (1);
  }
  int j;
  for (j = 0; j < RECORDED_DELAY_SIZE; j++)
  {
    fprintf (f, "%lld\n", recorded_delays[j]);
  }
  fclose (f);
#endif
  critical_pprint ("If we reach here, program is ending");
  return 0;
}
