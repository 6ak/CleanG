#ifndef LTE_CORE
#define LTE_CORE

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
#include <rte_mempool.h>
#include <rte_cycles.h>
#include <rte_ether.h>

#include <stdio.h>
//TODO: ALI! VERY IMPORTANT! EVENT RATES ARE CHANGED!
#define ALI_ETHER_TYPE 0x6666
/******************** High level emulation parameteres *****/
//TODO: NOT DEFAULT VALUE 2K OR 5K
#define NUMBER_OF_USERS_PER_ROUND 5000000
#define NUMBER_OF_ROUNDS 1
// this is the data rate

//Based on my current calculations, 7 pkt per second for active users look good. 
#define DEFAULT_USER_RATE 150
#define SCENARIO_DEFAULT_RATE_MULTIPLIER 0.01

#define CLEAN_G 0
#define LTE 1
#define SDN 2
#define SIMULATION_MODE CLEAN_G
#define ACTIVATED 1
#define DISABLED 0
#define ENABLED 1
#define MULTI_INSTANCE_CLEANG ENABLED
#define SEND_DATA_PACKETS ENABLED
#define MAX_NUM_HANDOVER 100000
#define MAXIMUM_RUN_TIME_IN_SECONDS 3600
// For now, if time logging is activated the number of users cannot be very large
//This time logging was added for SDN case initially
#define TIME_LOGGING DISABLED
// This time logging is for all cases to be able to follow messages timings for users
#define COMPLETE_T_LOGGING DISABLED
#define UTILIZATION_LOGGING DISABLED
#define DATA_DELAY_LOGGING DISABLED
#define ADD_SEQUENCE_NUMBER DISABLED
#define PACKET_DUMP_DEBUG DISABLED
//default is 1000
#define SCENARIO_RATE_STEPS 9000
#define DATA_SENDER_CORE_NUMBER 3
// maximum number of different messages codes that can be handled in NFs for the sake of time logging
#define MAX_NUMBER_OF_MESSAGE_CODES 25
#define CLEANG_MULTIPORT ACTIVATED
#define PRINT_TARGET_USER_ID 500
#define PRINT_DATA_NUMBER_OF_ACTIVE_USERS DISABLED
#define STORE_RESULTS_ENB DISABLED
#define CLOCK_READ_REDUCER 100000
//TODO: ALI NORMALLY THIS VALUE IS 2, CHANGED TO 3 FOR BERKLEY PAPER
#define REPLIED_PER_PACKET 3
// TODO: Ali the following line is a trick! Probably it is better to be fixed?
#define TOTAL_NUMBER_OF_REATTACHS 5
#define MESSAGE_BASED 0
#define MESSAGE_LESS 1
#define CLEANG_MODE MESSAGE_LESS
#define CLEANG_EXTENDED_HASH ACTIVATED
/******************** debug printing ************************/
#define USER_PRINT 0
#define CRITICALPRINT 0
#define ALIDEBUG 0
#define ALIDEBUG2 0
#define DATA_REPLIER_MEM_ALLOCATION_DEBUG CRITICALPRINT

/*
How to activate one of these levels in a single file
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Werror"
#undef CRITICALPRINT
#define CRITICALPRINT 1
#pragma GCC diagnostic pop
*/

#define critical_print(fmt, ...) \
  do { \
    if (CRITICALPRINT) {\
      fprintf(stderr, "%s:%d: ", __FILE__, __LINE__); \
      fprintf(stderr, fmt, __VA_ARGS__); \
    }\
  } while (0)

#define MY_HASH_FUNCTION(key) (key)

#define critical_pprint(fmt) \
  do { \
    if (CRITICALPRINT) { \
      fprintf(stderr, "%s:%d: ", __FILE__, __LINE__); \
      fprintf(stderr, fmt); \
    }\
  } while (0)

#define ali_debug_print(fmt, ...) \
  do { \
    if (ALIDEBUG) {\
      fprintf(stderr, "%s:%d: ", __FILE__, __LINE__); \
      fprintf(stderr, fmt, __VA_ARGS__); \
    }\
  } while (0)

#define ali_debug_print_user(userId, fmt, ...) \
  do { \
    if (ALIDEBUG || (USER_PRINT && userId == PRINT_TARGET_USER_ID)) {\
      fprintf(stderr, "%s:%d: ", __FILE__, __LINE__); \
      fprintf(stderr, fmt, __VA_ARGS__); \
    }\
  } while (0)

#define ali_debug_pprint(fmt) \
  do { \
    if (ALIDEBUG) { \
      fprintf(stderr, "%s:%d: ", __FILE__, __LINE__); \
      fprintf(stderr, fmt); \
    }\
  } while (0)

#define ali_debug_pprint_user(userId, fmt) \
  do { \
    if (ALIDEBUG || (USER_PRINT && userId == PRINT_TARGET_USER_ID)) { \
      fprintf(stderr, "%s:%d: ", __FILE__, __LINE__); \
      fprintf(stderr, fmt); \
    }\
  } while (0)

#define ali_debug_print2(fmt, ...) \
  do { \
    if (ALIDEBUG2) {\
      fprintf(stderr, "%s:%d: ", __FILE__, __LINE__); \
      fprintf(stderr, fmt, __VA_ARGS__);\
    }\
  } while (0)

#define ali_debug_pprint2(fmt) \
  do { \
    if (ALIDEBUG2){ \
      fprintf(stderr, "%s:%d: ", __FILE__, __LINE__); \
      fprintf(stderr, fmt); \
    } \
  } while (0)
#define SHOW_PACKET_STATS DISABLED
#define SHOW_USER_STATS_IN_SCEN_GEN ENABLED

/*********************************************************/
#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
#include <rte_hash_crc.h>
#define DEFAULT_HASH_FUNC       rte_hash_crc
#else
#include <rte_jhash.h>
#define DEFAULT_HASH_FUNC       rte_jhash
#endif


/**************** scenario parameters ***********************/
#define RECORDED_DELAY_SIZE 1000000
#define SDN_F3_TOWARD_CONTROL_PORT 2
#define SDN_F3_TOWARD_ENB_PORT 1
#define PORT_TOWARD_OF_SERVER 0
#define SDN_F4_TOWARD_DATA_PORT 1
#define SDN_F4_TOWARD_OF_SERVER 0
// In Original scenario its value was 0, but I changed it to 1 in hope of using same compoenents for SDN and LTE
#define LTE_TOWARD_ENB 1
// ignore following three lines, data_packet_port was defined for the same purpose
// A port number that we are sure is not used, so these packets are not mixed with other packets!
// The reason was replier in lte was not working properly, maybe this can fix it
//#define OTHER_PORT_NO 10
#define CLEANG_TOWARD_ENB 1


#define MAXIMUM_WAIT_BETWEEN_STEPS 1000
#define WAIT_ATTACH_HANDOVER 1000
#define WAIT_HANDOVER_ACTIVE_TO_IDLE 1000
#define WAIT_ACTIVE_TO_IDLE_IDLE_TO_ACTIVE 1000
#define WAIT_IDLE_TO_ACTIVE_TO_DETACH 1000
#define WAIT_BETWEEN_ROUNDS 5000
//#define L1_DISC_TO_CONN_RATE 10
// R1 in calculations, 0.07, default multiplier is .01, so we set this to 7
#define L1_DISC_TO_CONN_RATE 7.0

//TODO: NOT DEFAULT VALEU:
//#define L2_CONN_TO_IDLE_RATE 100
// r3 in the calculations        
#define L2_CONN_TO_IDLE_RATE 0.0
//#define L2_CONN_TO_IDLE_RATE 21.5
// r4 in the calculations
#define L3_IDLE_TO_CONN_RATE 2.69
// r7 in the calculations
#define L4_CONN_TO_CONN_RATE 0.0
//#define L4_CONN_TO_CONN_RATE 7.0
// R2 in the calculations
#define L5_CONN_TO_DISC_RATE 0.0
//#define L5_CONN_TO_DISC_RATE 7.0
#define SCENARIO_STATE_DISC 1
#define SCENARIO_STATE_CONN 2
#define SCENARIO_STATE_IDLE 3
#define MAXIMUM_DELAY_BETWEEN_SAME_USER_PACKETS 1000000000
//Probably always keep it disabled
#define PACKET_COUNTER_STATS DISABLED
#define COMPLETE_MAX_NUMBER_OF_MESSAGE_CODE 200

#define TOTAL_NUMBER_OF_DATA_CENTER_ENGINES 3
struct DataSenderSpecifier {
  int totalNumberOfShards;
  int selectedShard;
};

struct scenarioGenUserState {
  uint64_t imsi;
  struct timespec lastCheck;
  uint32_t currentState;
  long L1RatePerSecond;
  long L2RatePerSecond;
  long L3RatePerSecond;
  long L4RatePerSecond;
  long L5RatePerSecond;
};

struct timeLoggingState {
  struct timespec time;
  uint32_t code;
};

struct reliabilityLayer {
  uint64_t seqno;
};
/*************** mixed functions and structures **************/
//indexes should not be used to access data in data structure, but to save time,
//we are using this index to access imsi after messageCode. It is 8, because our
//system is 64bit, so even messageCode is 32bit, the index for imsi is 8 bytes
#define IMSI_INDEX 8
#define NUMBER_OF_USERS NUMBER_OF_USERS_PER_ROUND*NUMBER_OF_ROUNDS
// if the above number is too large, the nf may not be able to reserve enough memory
// I got the error with 100
#define NO_OF_HASH_ENTRIES_IN_CORE_FORWARDER NUMBER_OF_USERS * TOTAL_NUMBER_OF_REATTACHS
#define NEW_USER_COMMAND 1
#define HANDOVER_COMMAND 2
#define DETACH_COMMAND 3
#define ACTIVE_TO_IDLE_COMMAND 4
#define IDLE_TO_ACTIVE_COMMAND 5
#define COMMAND_MESSAGE_PORT 4
#define IP_10_0_0_0 167772160
#define MME1IP (IP_10_0_0_0 + 3)
#define ENB1IP (IP_10_0_0_0 + 6)
#define ENB2IP (IP_10_0_0_0 + 10)
#define EUC1IP (IP_10_0_0_0 + 3) // core 1 IP, CHANGE IT FROM 3
#define EUC2IP (IP_10_0_0_0 + 10) // core 2 IP
#define SGW1IP (IP_10_0_0_0 + 7)
#define PGW1IP (IP_10_0_0_0 + 8)
#define REP1IP (IP_10_0_0_0 + 4)
//                     3232235776
#define IP_192_168_1_1 3232235777
#define CORE_FORWARDER_SERVICE_iD 1
//it was 2 before
#define LTE_ENB1_SERVICE_ID 4
//it was 5 before
#define LTE_ENB2_SERVICE_ID 10
#define LTE_MME1_SERVICE_ID 2
//it was 4 before
#define LTE_SGW1_SERVICE_ID 5
// it was 5
#define LTE_PGW1_SERVICE_ID 9
//it was 3 before
#define LTE_DATA_SERVICE_ID 7
// it was 3 before
#define LTE_REP1_SERVICE_ID 12
// it was 6 before
#define LTE_REP2_SERVICE_ID 14
#define LTE_REP3_SERVICE_ID 7
#define EUTRAN_CONTROL_1_SERVICE_ID 2
#define EUTRAN_CONTROL_2_SERVICE_ID 5
struct scenarioMessage {
  uint32_t command;
  uint32_t userID;
};



void corePrint2(void);
inline static void prependIPHeader (struct rte_mbuf* pkt, uint32_t src, uint32_t dst, uint8_t nextProto);
inline static void prependETHF2toF3(struct rte_mbuf* pkt);
inline static void prependETHF3toF2(struct rte_mbuf* pkt);
inline static void prependETHF3toF2SDN(struct rte_mbuf* pkt);
inline static void prependETHF4toF3(struct rte_mbuf* pkt);
inline static void prependETHF4toF32(struct rte_mbuf* pkt);

void  printOutputEnb(FILE* f, struct timespec* startTimes_t,struct timespec* startTimes_a,struct timespec* startTimes_i,struct timespec* startTimes_d,struct timespec* startTimes_h, 
    struct timespec* hstartTimes_t,struct timespec* hstartTimes_a,struct timespec* hstartTimes_i,struct timespec* hstartTimes_d,struct timespec* hstartTimes_h
    , struct timespec* endTimes_t,struct timespec* endTimes_a,struct timespec* endTimes_i,struct timespec* endTimes_d,struct timespec* endTimes_h, 
    struct timespec* hendTimes_t,struct timespec* hendTimes_a,struct timespec* hendTimes_i,struct timespec* hendTimes_d,struct timespec* hendTimes_h);
void addGTPUHeader(struct rte_mbuf* pkt, uint32_t teid);
/**************  Traditional LTE  ***************************/
#define IP_TYPE_NAS 5
#define IP_TYPE_GCONTROL 6
#define IP_TYPE_GUSER 7
#define LTE_3_ATTACH_CODE 1
#define LTE_6_AUTH_REQ_CODE 2
#define LTE_7_AUTH_RES_CODE 3
#define LTE_8_SEC_MOD_CODE 4
#define LTE_9_KEY_GEN_CODE 5
#define LTE_12_EPS_REQ_CODE 6
#define LTE_13_EPS_REQ_CODE 7
#define LTE_18_EPS_RES_CODE 8
#define LTE_19_EPS_RES_CODE 9
#define LTE_20_ATCH_ACPT_CODE 10
#define LTE_21_ERAB_REQ_CODE 11
#define LTE_25_CONTEXT_RES_CODE 12
#define LTE_26_ATTACH_COMPLETE_CODE 13
#define LTE_27_BEARER_MOD_CODE 14
#define LTE_28_MOD_RES_CODE 15
#define TLTE29_MESSAGE_CODE 16
//TODO: user_state_size is larger than number of users because users may reconnect after detaching!
//Still if we wait long enough, we will get errors and nfs will stop working maybe somewhere not related!
#define USER_STATE_SIZE NUMBER_OF_USERS*TOTAL_NUMBER_OF_REATTACHS
#define PGW1_FIRST_IP  IP_192_168_1_1
#define SEND_DATA_COMMAND 50
#define STOP_DATA_COMMAND 51
#define RESUME_DATA_COMMAND 52
#define DATA_COMMAND_PORT 7
#define DATA_PACKET_PORT 8
#define DATA_PACKET_SIZE 256
#define SENT_PACKET_NO 1
#define CORE_FORWARDER_SERVICE_ID 1
#define INACTIVE 0
#define ACTIVE 1
struct dataPacket {
  char data [DATA_PACKET_SIZE];
};

struct dataGeneratorState {
  uint32_t ip;
  uint32_t active;
  struct timespec lastSentDataPacket;
  long ratePerSecond;
  long long totalSentPacket;
};
//struct forwardingCoreDataStructure {
//  uint32_t enbIP;
//};

struct CoreDataPathSet {
  uint32_t messageCode;
  uint32_t ueIP;
  uint32_t enbIP;
  //  uint32_t 
};

//6f
#define PGW_OP_LTE13_CODE 111
//70
#define SGW_OP_LTE5_CODE 112
//71
#define SGW_OP_LTE18_CODE 113
//72
#define SGW_OP_LTE28_CODE 114

//73
#define PGW_OP_LTE13_BACK_CODE 115
//74
#define SGW_OP_LTE5_BACK_CODE 116
//75
#define SGW_OP_LTE18_BACK_CODE 117
//76
#define SGW_OP_LTE28_BACK_CODE 118

//77
#define PGW_OP_DETACH_CODE 119
//78
#define SGW_OP_DETACH_CODE 120
//79
#define SGW_OP_ITOA_CODE 121
//7a
#define SGW_OP_ATOI_CODE 122
//7b
#define SGW_OP_H22_CODE 123
//7c
#define SGW_OP_H18_CODE 124

//7d
#define PGW_OP_DETACH_BACK_CODE 125
//7e
#define SGW_OP_DETACH_BACK_CODE 126
//7f
#define SGW_OP_ITOA_BACK_CODE 127
//80
#define SGW_OP_ATOI_BACK_CODE 128
//81
#define SGW_OP_H22_BACK_CODE 129
//82
#define SGW_OP_H18_BACK_CODE 130


struct GwOpPlaceHolder {
  uint32_t messageCode;
  uint64_t imsi;
  //uint32_t ip;
  //uint32_t s5dl;
};

//6f
struct PgwOpLte13 {
  uint32_t messageCode;
  uint64_t imsi;
  uint32_t ip;
  uint32_t s5dl;
};

//70
struct SgwOpLte5 {
  uint32_t messageCode;
  uint64_t imsi;
  uint32_t s1dl;
  uint32_t s1ul;
};

//71
struct SgwOpLte18 {
  uint32_t messageCode;
  uint64_t imsi;
  uint32_t s1ul;
  uint32_t s5ul;
  uint32_t ip;
};
//72
struct SgwOpLte28 {
  uint32_t messageCode;
  uint64_t imsi;
  uint32_t s1dl;
  uint32_t s5dl;
};

#define SET_CORE_PATH_COMMAND 22

struct lte3Attach {
  uint32_t messageCode;
  uint64_t imsi; //15 digits
  uint32_t tai;
  uint64_t ecgi; //no more than 52 bits

};

struct lte6AuthRequest {
  uint32_t messageCode;
  uint64_t imsi; //15 digits
  uint32_t rand;
  char autn [256];

};

struct lte7AuthResponse {
  uint32_t messageCode;
  uint64_t imsi; //15 digits
  char res [256];

};

struct lte8SecMod {
  uint32_t messageCode;
  uint64_t imsi; //15 digits

};

struct lte9KeyGen {
  uint32_t messageCode;
  uint64_t imsi; //15 digits

};

struct lte12EpsReq {
  uint32_t messageCode;
  uint64_t imsi; //15 digits

};

struct lte13EpsReq {
  uint32_t messageCode;
  uint64_t imsi; //15 digits
  uint32_t s5dl;
};

struct lte18EpsRes {
  uint32_t messageCode;
  uint64_t imsi; //15 digits
  uint32_t s5ul;
  uint32_t ip;
};

struct lte19EpsRes {
  uint32_t messageCode;
  uint64_t imsi; //15 digits
  uint32_t ip;
  uint32_t s1ul;
};

struct lte20AttachAccept {
  uint32_t messageCode;
  uint64_t imsi; //15 digits
  uint32_t ip;
};

struct lte21ErabReq {
  uint32_t messageCode;
  uint64_t imsi; //15 digits
  uint32_t s1u1;
};

struct lte25ContextRes {
  uint32_t messageCode;
  uint64_t imsi; //15 digits
  uint32_t s1dl;

};

struct lte26AttachComplete {
  uint32_t messageCode;
  uint64_t imsi; //15 digits

};

struct lte27BrearerMod {
  uint32_t messageCode;
  uint64_t imsi; //15 digits
  uint32_t s1dl;
};

struct lte28ModRes {
  uint32_t messageCode;
  uint64_t imsi; //15 digits

};

struct tLTE29 {
  uint32_t messageCode;
  uint64_t imsi; //15 digits

};

struct lteENBState {
  uint32_t id;
  uint8_t noOfCores; //number of connected cores
  uint32_t coreIPAddresses [1];
};

struct lteMMEUserState {
  uint64_t imsi;
  char kenb [256];
  uint32_t ip;
  char guti[80] ; //not more than 80 bits
  char qosinfo [256];
  uint32_t tai;
  uint64_t ecgi; //no more than 52 bits
  uint32_t rand;
  char autn [256];
  uint32_t state;
  uint32_t targets1dl;

};

#define ENB_STATE_TRANSITION_T 30
#define ENB_STATE_TRANSITION_H 31
#define ENB_STATE_TRANSITION_A 32
#define ENB_STATE_TRANSITION_I 33
#define ENB_STATE_TRANSITION_D 34
#define ENB_STATE_DISC 35
#define ENB_STATE_CONN 36
#define ENB_STATE_IDLE 37

struct lteENBUserState {
  uint64_t imsi;
  char kenb [256];
  uint32_t ip;
  char guti[80] ; //not more than 80 bits
  char qosinfo [256];
  uint32_t tai;
  uint64_t ecgi; //no more than 52 bits
  uint32_t rand;
  char autn [256];
  uint32_t state;
  uint32_t s1ul;
  uint32_t s1dl;
};


struct lteSGWUserState {
  uint64_t imsi;
  uint32_t ip;
  char guti[80] ; //not more than 80 bits
  char qosinfo [256];
  uint32_t tai;
  uint64_t ecgi; //no more than 52 bits
  uint32_t state;
  uint32_t s5dl;
  uint32_t targets1dl;
};

struct ltePGWUserState {
  uint64_t imsi;
  uint32_t ip;
  char guti[80] ; //not more than 80 bits
  char qosinfo [256];
  uint32_t tai;
  uint64_t ecgi; //no more than 52 bits
  uint32_t state;
};

struct GTPUHeader {
  //  uint8_t type; //we learn the type by using ip.next_proto
  uint32_t teid;
};

struct sendDataCommand {
  uint32_t commandCode;
  uint64_t imsi;
  uint32_t ip;
};


// using sendDataCommand structure for both purposes//struct stopDataCommand {
//  uint32_t commandCode;
//  uint32_t ip;
//  uint64_t imsi;
//
//};


#define HLTE2_MESSAGE_CODE 25
#define HLTE3_MESSAGE_CODE 26
#define HLTE4_MESSAGE_CODE 27
#define HLTE5_MESSAGE_CODE 28
#define HLTE6_MESSAGE_CODE 29
#define HLTE7_MESSAGE_CODE 30
#define HLTE9_MESSAGE_CODE 31
#define HLTE10_MESSAGE_CODE 32
#define HLTE12_MESSAGE_CODE 33
#define HLTE13_MESSAGE_CODE 34
#define HLTE14_MESSAGE_CODE 35
#define HLTE17_MESSAGE_CODE 36
#define HLTE18_MESSAGE_CODE 37
#define HLTE19_MESSAGE_CODE 38
#define HLTE20_MESSAGE_CODE 39
#define HLTE21_MESSAGE_CODE 40
#define HLTE22_MESSAGE_CODE 41
#define HLTE23_MESSAGE_CODE 80

#define DLTE1_MESSAGE_CODE 42
#define DLTE2_MESSAGE_CODE 43
#define DLTE3_MESSAGE_CODE 44
#define DLTE4_MESSAGE_CODE 45
#define DLTE5_MESSAGE_CODE 46
#define DLTE6_MESSAGE_CODE 47
#define DLTE7_MESSAGE_CODE 48
#define DLTE8_MESSAGE_CODE 49
#define DLTE9_MESSAGE_CODE 50
#define DLTE10_MESSAGE_CODE 51
#define DLTE11_MESSAGE_CODE 52
#define DLTE12_MESSAGE_CODE 81 //NOT AN ACTUAL MESSAGE

#define ALTE1_MESSAGE_CODE 53
#define ALTE2_MESSAGE_CODE 54
#define ALTE3_MESSAGE_CODE 55
#define ALTE4_MESSAGE_CODE 56
#define ALTE5_MESSAGE_CODE 57
#define ALTE6_MESSAGE_CODE 58
#define ALTE7_MESSAGE_CODE 82

#define ILTE1_MESSAGE_CODE 59
#define ILTE2_MESSAGE_CODE 60
#define ILTE3_MESSAGE_CODE 61
#define ILTE4_MESSAGE_CODE 62
#define ILTE5_MESSAGE_CODE 63
#define ILTE6_MESSAGE_CODE 64
#define ILTE7_MESSAGE_CODE 65
#define ILTE8_MESSAGE_CODE 66
#define ILTE9_MESSAGE_CODE 67
#define ILTE10_MESSAGE_CODE 68
#define ILTE11_MESSAGE_CODE 69
#define ILTE12_MESSAGE_CODE 70
#define ILTE13_MESSAGE_CODE 71
#define ILTE14_MESSAGE_CODE 72
#define ILTE15_MESSAGE_CODE 73
#define ILTE16_MESSAGE_CODE 74
#define ILTE17_MESSAGE_CODE 75
#define ILTE18_MESSAGE_CODE 83


struct hLTE2
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
  uint32_t targetENB; 
};

struct hLTE3
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
  uint32_t s1ul;
  uint32_t ip; //in reality it should be ERAB ID or something like that
};

struct hLTE4
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
  uint32_t s1dl;
  uint32_t indirects1dl;
};

struct hLTE5
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
  uint32_t indirects1dl;
};

struct hLTE6
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
  uint32_t s1ul;
};

struct hLTE7
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
  uint32_t s1ul;
};

struct hLTE9
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct hLTE10
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct hLTE12
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct hLTE13
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
  uint32_t targets1dl;
};

struct hLTE14
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct hLTE17
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct hLTE18
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct hLTE19
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct hLTE20
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct hLTE21
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct hLTE22
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct hLTE23
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};


//--------------------------------Detach

struct dLTE1
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct dLTE2
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct dLTE3
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct dLTE4
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct dLTE5
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct dLTE6
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct dLTE7
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct dLTE8
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct dLTE9
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct dLTE10
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct dLTE11
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct dLTE12
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};



//-----------------------------  Idle to active

struct iLTE1
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct iLTE2
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct iLTE3
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct iLTE4
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct iLTE5
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct iLTE6
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct iLTE7
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct iLTE8
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct iLTE9
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct iLTE10
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct iLTE11
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct iLTE12
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct iLTE13
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct iLTE14
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct iLTE15
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct iLTE16
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct iLTE17
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct iLTE18
{
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};


//------------------------------- active to idle

struct aLTE1
{
  uint32_t messageCode;

  uint64_t imsi; //15 digits
};

struct aLTE2
{
  uint32_t messageCode;

  uint64_t imsi; //15 digits
};

struct aLTE3
{
  uint32_t messageCode;

  uint64_t imsi; //15 digits
};

struct aLTE4
{
  uint32_t messageCode;

  uint64_t imsi; //15 digits
};

struct aLTE5
{
  uint32_t messageCode;

  uint64_t imsi; //15 digits
};

struct aLTE6
{
  uint32_t messageCode;

  uint64_t imsi; //15 digits
};

struct aLTE7
{
  uint32_t messageCode;

  uint64_t imsi; //15 digits
};


/**************  Our approach  ******************************/
#define CORE1IP (IP_10_0_0_0 + 3)

//This struct is the state store in eNB
struct CleaneNBState {
  uint32_t id;
  uint8_t noOfCores; //number of connected cores
  uint32_t coreIPAddresses [1];//10.0.0.3
};

struct CleaneNBUserState {

};

// Message codes for attach 
#define TLTE5_MESSAGE_CODE_C 11
#define TLTE8_MESSAGE_CODE_C 12
#define HLTE2_MESSAGE_CODE_C 21
#define HLTE3_MESSAGE_CODE_C 22
#define HLTE4_MESSAGE_CODE_C 23
#define HLTE5_MESSAGE_CODE_C 24
#define HLTE7_MESSAGE_CODE_C 25
#define HLTE11_MESSAGE_CODE_C 26
// Handlign ILTE by using data packets
#define DLTE2_MESSAGE_CODE_C 31
#define DLTE5_MESSAGE_CODE_C 32
// Can the same timer be used in core to avoid sending this message?
#define ILTE5_MESSAGE_CODE_C 41
#define ILTE7_MESSAGE_CODE_C 42
#define ALTE1_MESSAGE_CODE_C 51
#define ALTE2_MESSAGE_CODE_C 52


#define CleanCoreStateActive 0
#define CleanCoreStatePause 1
#define CLEANCORESTATEDELETED 2

struct cleanCoreState {
  uint32_t state;
  uint32_t ip;
  uint32_t enbIP;
  uint64_t imsi;
};


struct tLTE5C {
  uint32_t messageCode;
  uint64_t imsi; //15 digits
  uint32_t tai;
  uint64_t ecgi; //no more than 52 bits
  uint32_t rand;
  uint32_t enbIP;
  char autn [256];
} ;

struct tLTE8C {
  uint32_t messageCode;
  uint64_t imsi; //15 digits
  uint64_t res; //not really sure it is 64 bit
  char kenb [256];
  uint32_t ip;
  char guti[80] ; //not more than 80 bits
  char qosinfo [256];
} ;

struct hLTE2C {
  uint32_t messageCode;
  uint64_t imsi; //15 digits
} ;

struct hLTE3C {
  uint32_t messageCode;
  uint64_t imsi; //15 digits
} ;

struct hLTE4C {
  uint32_t messageCode;
  uint64_t imsi; //15 digits
} ;

struct hLTE5C {
  uint32_t messageCode;
  uint64_t imsi; //15 digits
} ;

struct hLTE7C {
  uint32_t messageCode;
  uint64_t imsi; //15 digits
} ;

struct hLTE11C {
  uint32_t messageCode;
  uint64_t imsi; //15 digits
} ;





struct dLTE2C {
  uint32_t messageCode;
  uint64_t imsi; //15 digits
} ;

struct dLTE5C {
  uint32_t messageCode;
  uint64_t imsi; //15 digits
} ;

struct iLTE5C {
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct iLTE7C {
  uint32_t messageCode;
  uint64_t imsi; //15 digits
  uint32_t ip;
};

struct aLTE1C {
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

struct aLTE2C {
  uint32_t messageCode;
  uint64_t imsi; //15 digits
};

//extern void delayNanoSec (long delay);

static inline long returnNanoDifference (struct timespec begining, struct timespec end) {
  long timeDifferenceSec = (end.tv_sec - begining.tv_sec) * 1000000000;
  long timeDifferenceNSec = end.tv_nsec - begining.tv_nsec;
  long timeDifference = timeDifferenceSec + timeDifferenceNSec;
  if (timeDifference < 0) {
    critical_print ("begining nano is %ld beginning sec is %ld\n",begining.tv_nsec, begining.tv_sec );
    critical_print ("end nano is %ld end sec is %ld\n",end.tv_nsec, end.tv_sec);
    return 0;
  }
  return timeDifference;
}

static inline long long llreturnNanoDifference (struct timespec begining, struct timespec end) {
  long long timeDifferenceSec = (end.tv_sec - begining.tv_sec) * 1000000000;
  long timeDifferenceNSec = end.tv_nsec - begining.tv_nsec;
  long long timeDifference = timeDifferenceSec + timeDifferenceNSec;
  if (timeDifference < 0) {
    // TODO: temporary the severity of the following lines are reduced, they should be investigated
    ali_debug_print ("time difference is %lld\n",timeDifference);
    ali_debug_print ("time difference sec is %lld\n", timeDifferenceSec);
    ali_debug_print ("begining nano is %ld beginning sec is %ld\n",begining.tv_nsec, begining.tv_sec );
    ali_debug_print ("end nano is %ld end sec is %ld\n",end.tv_nsec, end.tv_sec);
    return 0;
  }
  return timeDifference;
}


static inline void delayNanoSec (long delay) {
  //printf("hello %ld \n", delay);
  struct timespec sleepStartTime;
  struct timespec sleepDuringTime;
  clock_gettime(CLOCK_REALTIME, &sleepStartTime);
  long w = 0;
  for (w=0; w < LONG_MAX; w++) {
    clock_gettime( CLOCK_REALTIME, &sleepDuringTime);
    long timeDifferenceSec = (sleepDuringTime.tv_sec - sleepStartTime.tv_sec) * 1000000000;
    long timeDifferenceNSec = sleepDuringTime.tv_nsec - sleepStartTime.tv_nsec;
    long timeDifference = timeDifferenceSec + timeDifferenceNSec;
    if (timeDifference > delay)
      break;
  }
  if (w==LONG_MAX) {
    printf("Something is wrong with delaying approach!\n");
  }
}
/*
static inline static void recordEvent (uint32_t scode, uint64_t imsi,  tl) {
  //tl[imsi].code = scode;
  clock_gettime(CLOCK_REALTIME, &tl[imsi][scode]);
}
*/
static inline void printSimulParams (FILE * f) {
  // same simulation parameters
  fprintf (f, "no of users: %d\n", NUMBER_OF_USERS);
  fprintf (f, "default user rate: %d\n", DEFAULT_USER_RATE);
  fprintf (f, "simulation mode: %d\n", SIMULATION_MODE);
  fprintf (f, "send data packets: %d\n", SEND_DATA_PACKETS);
  fprintf (f, "disc to conn rate: %f\n", L1_DISC_TO_CONN_RATE);
  fprintf (f, "conn to idle rate: %f\n", L2_CONN_TO_IDLE_RATE);
  fprintf (f, "idle to conn rate: %f\n", L3_IDLE_TO_CONN_RATE);
  fprintf (f, "conn to conn rate: %f\n", L4_CONN_TO_CONN_RATE);
  fprintf (f, "conn to disc rate: %f\n", L5_CONN_TO_DISC_RATE);
  fprintf (f, "default rate multiplier: %f\n", SCENARIO_DEFAULT_RATE_MULTIPLIER);
}


static inline void writeTimeLogToFile (const char* fileName, struct timespec tl [NUMBER_OF_USERS][MAX_NUMBER_OF_MESSAGE_CODES]) {
  FILE *f = fopen(fileName, "w");
  if (f == NULL)
  {
    printf("Error opening file!\n");
    exit(1);
  }
  printSimulParams(f);
  int j;
  for (j=0; j < NUMBER_OF_USERS; j++)
  {
    fprintf (f, "%d, ", j);
    int i;
    for (i=0; i < MAX_NUMBER_OF_MESSAGE_CODES; i++) {
      fprintf (f, "%d,%ld,%ld ", i, tl[j][i].tv_sec, tl[j][i].tv_nsec);
    }
    fprintf (f, "\n");
  }
  fclose (f);
}


static inline void writeCompleteTimeLogToFile (const char* fileName, struct timespec **ctl) {
  FILE *f = fopen(fileName, "w");
  if (f == NULL)
  {
    printf("Error opening file!\n");
    exit(1);
  }
  printSimulParams(f);
  int j;
  for (j=0; j < NUMBER_OF_USERS; j++)
  {
    fprintf (f, "%d, ", j);
    int i;
    for (i=0; i < COMPLETE_MAX_NUMBER_OF_MESSAGE_CODE; i++) {
      //The order of i and j are changed, because that's how ctl is defined.
      fprintf (f, "%d,%ld,%ld ", i, ctl[i][j].tv_sec, ctl[i][j].tv_nsec);
    }
    fprintf (f, "\n");
  }
  fclose (f);
}



static inline void recordUtilizationLog (const char* fileName, double utilization[MAXIMUM_RUN_TIME_IN_SECONDS]) {
  FILE *f = fopen(fileName, "w");
  if (f == NULL)
  {
    printf("Error opening file!\n");
    exit(1);
  }
  printSimulParams(f);
  int j;
  for (j=0; j < MAXIMUM_RUN_TIME_IN_SECONDS; j++)
  {
    fprintf (f, "%d, ", j);
    //int i;
    //for (i=0; i < MAX_NUMBER_OF_MESSAGE_CODES; i++) {
      fprintf (f, "%1.9f ", utilization[j]);
    //}
    fprintf (f, "\n");
  }
}

static inline void printMbuf (struct rte_mbuf* mbuf) {
  //int i= 0;
  printf ("Packet contents with the length of %d are:\n", rte_pktmbuf_data_len(mbuf));
  /*
  for (i = 0; i < rte_pktmbuf_data_len(mbuf); i++) {
    printf ("%04x", *(rte_ctrlmbuf_data(mbuf)+i));
  }
  */
  printf ("content printing is removed in this version\n");
  printf ("end of packet contents\n");
}

static inline void prependETHF2toF3(struct rte_mbuf* pkt){
  struct ether_hdr *eh;
  eh = (struct ether_hdr *)rte_pktmbuf_prepend(pkt, sizeof(struct ether_hdr));
  //eh->ether_type = ETHER_TYPE_IPv4;
  struct ether_addr s;
  struct ether_addr d;
  d.addr_bytes[0] = 0x8c;
  d.addr_bytes[1] = 0xdc;
  d.addr_bytes[2] = 0xd4;
  d.addr_bytes[3] = 0xac;
  //  d.addr_bytes[4] = 0xc2;
  //  d.addr_bytes[5] = 0x10;
  d.addr_bytes[4] = 0x6c;
  d.addr_bytes[5] = 0x7c;

  s.addr_bytes[0] = 0x8c;
  s.addr_bytes[1] = 0xdc;
  s.addr_bytes[2] = 0xd4;
  s.addr_bytes[3] = 0xac;
  s.addr_bytes[4] = 0xc0;
  s.addr_bytes[5] = 0x94;

  ether_addr_copy(&s, &eh->s_addr);
  ether_addr_copy(&d, &eh->d_addr);

  // TODO: ALI, should this one be changed to ALI_ETHER_TYPE similar to other ethernet capsulator?
  //  eh->ether_type = rte_be_to_cpu_16(ETHER_TYPE_IPv4);
  eh->ether_type = ALI_ETHER_TYPE;

}

static inline void prependETHF3toF2 (struct rte_mbuf* pkt) {
  struct ether_hdr *eh;
  eh = (struct ether_hdr *)rte_pktmbuf_prepend(pkt, sizeof(struct ether_hdr));
  eh->ether_type = ALI_ETHER_TYPE;
  struct ether_addr s;
  struct ether_addr d;
  s.addr_bytes[0] = 0x8c;
  s.addr_bytes[1] = 0xdc;
  s.addr_bytes[2] = 0xd4;
  s.addr_bytes[3] = 0xac;
  //  s.addr_bytes[4] = 0xc2;
  //  s.addr_bytes[5] = 0x10;
  s.addr_bytes[4] = 0x6c;
  s.addr_bytes[5] = 0x7c;

  d.addr_bytes[0] = 0x8c;
  d.addr_bytes[1] = 0xdc;
  d.addr_bytes[2] = 0xd4;
  d.addr_bytes[3] = 0xac;
  d.addr_bytes[4] = 0xc0;
  d.addr_bytes[5] = 0x94;
  ether_addr_copy(&s, &eh->s_addr);
  ether_addr_copy(&d, &eh->d_addr);
  return;
}


static inline void prependETHF3toF2SDN (struct rte_mbuf* pkt) {
  struct ether_hdr *eh;
  eh = (struct ether_hdr *)rte_pktmbuf_prepend(pkt, sizeof(struct ether_hdr));
  eh->ether_type = ALI_ETHER_TYPE;
  struct ether_addr s;
  struct ether_addr d;
  //'8c:dc:d4:ac:6c:7c'
  s.addr_bytes[0] = 0x8c;
  s.addr_bytes[1] = 0xdc;
  s.addr_bytes[2] = 0xd4;
  s.addr_bytes[3] = 0xac;
  //  s.addr_bytes[4] = 0x6c;
  //  s.addr_bytes[5] = 0x7c;
  s.addr_bytes[4] = 0x6b;
  s.addr_bytes[5] = 0x21;

  //'8c:dc:d4:ac:6b:94'
  d.addr_bytes[0] = 0x8c;
  d.addr_bytes[1] = 0xdc;
  d.addr_bytes[2] = 0xd4;
  d.addr_bytes[3] = 0xac;
  //   d.addr_bytes[4] = 0x6b;
  //  d.addr_bytes[5] = 0x94;
  d.addr_bytes[4] = 0x6c;
  // it didn't work with fd
  d.addr_bytes[5] = 0x7d;

  ether_addr_copy(&s, &eh->s_addr);
  ether_addr_copy(&d, &eh->d_addr);
  return;
}


static inline void prependETHF4toF3 (struct rte_mbuf* pkt) {
#if ADD_SEQUENCE_NUMBER == ACTIVATED
  struct reliabilityLayer *rl;
  static int lastSeqNo = 0;
  rl = (struct reliabilityLayer *)rte_pktmbuf_prepend(pkt, sizeof(struct reliabilityLayer));
  rl->seqno = lastSeqNo;
  lastSeqNo++;
#endif
  struct ether_hdr *eh;
  eh = (struct ether_hdr *)rte_pktmbuf_prepend(pkt, sizeof(struct ether_hdr));
  if (eh == NULL) {
    printf ("eh is null! problem in adding ethernet header!\n");
  }
  eh->ether_type = ALI_ETHER_TYPE;
  struct ether_addr s;
  struct ether_addr d;
  s.addr_bytes[0] = 0x8c;
  s.addr_bytes[1] = 0xdc;
  s.addr_bytes[2] = 0xd4;
  s.addr_bytes[3] = 0xac;
  s.addr_bytes[4] = 0x6b;
  s.addr_bytes[5] = 0x21;

  d.addr_bytes[0] = 0x8c;
  d.addr_bytes[1] = 0xdc;
  d.addr_bytes[2] = 0xd4;
  d.addr_bytes[3] = 0xac;
  d.addr_bytes[4] = 0x6c;
  d.addr_bytes[5] = 0x7d;
  ether_addr_copy(&s, &eh->s_addr);
  ether_addr_copy(&d, &eh->d_addr);
  return;
}

static inline void prependETHF4toF32 (struct rte_mbuf* pkt) {

  //struct reliabilityLayer *rl;
  //static int lastSeqNo = 100;
  //TODO: ali instead of size I have put 10 to see what happens
  /*rl = (struct reliabilityLayer *)*///rte_pktmbuf_prepend(pkt, 10);
  //rl->seqno = lastSeqNo;
  //lastSeqNo++;

  struct ether_hdr *eh;
  eh = (struct ether_hdr *)rte_pktmbuf_prepend(pkt, sizeof(struct ether_hdr));
  if (eh == NULL) {
    printf ("eh is null! problem in adding ethernet header!\n");
  }
  eh->ether_type = ALI_ETHER_TYPE;
  //eh->ether_type = ETHER_TYPE_IPv4;

  struct ether_addr s;
  struct ether_addr d;
  s.addr_bytes[0] = 0x8c;
  s.addr_bytes[1] = 0xdc;
  s.addr_bytes[2] = 0xd4;
  s.addr_bytes[3] = 0xac;
  s.addr_bytes[4] = 0x6b;
  s.addr_bytes[5] = 0x21;

  d.addr_bytes[0] = 0x8c;
  d.addr_bytes[1] = 0xdc;
  d.addr_bytes[2] = 0xd4;
  d.addr_bytes[3] = 0xac;
  d.addr_bytes[4] = 0x6c;
  d.addr_bytes[5] = 0x7d;
  ether_addr_copy(&s, &eh->s_addr);
  ether_addr_copy(&d, &eh->d_addr);
  return;
}

static inline void prependIPHeader (struct rte_mbuf* pkt, uint32_t src, uint32_t dst, uint8_t nextProto){
  struct ipv4_hdr *iph;
  iph = (struct ipv4_hdr *)rte_pktmbuf_prepend(pkt, sizeof(struct ipv4_hdr));
  iph->time_to_live = 50;
  iph->dst_addr = rte_be_to_cpu_32(dst);
  iph->src_addr = rte_be_to_cpu_32(src);
  iph->version_ihl = 69; //verion 4 length 5 words
  iph->next_proto_id = nextProto;
  return;
}
#endif /*LTE_CORE*/
