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

#define NF_TAG "basic_monitor"

/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

/* number of package between each print */
static uint32_t print_delay = 1000000;

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage: %s [EAL args] -- [NF_LIB args] -- -p <print_delay>\n\n", progname);
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c;

        while ((c = getopt (argc, argv, "p:")) != -1) {
                switch (c) {
                case 'p':
                        print_delay = strtoul(optarg, NULL, 10);
                        RTE_LOG(INFO, APP, "print_delay = %d\n", print_delay);
                        break;
                case '?':
                        usage(progname);
                        if (optopt == 'p')
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
packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta) {
        static uint32_t counter = 0;
        if (++counter == print_delay) {
                do_stats_display(pkt);
                counter = 0;
        }
	/*
	//ANON
	//printf("packet port is: %i", pkt->port);
        meta->action = ONVM_NF_ACTION_OUT;
        // Added by Ali
       	 //struct ipv4_hdr *iph;
	//iph = (struct ipv4_hdr *)rte_pktmbuf_append(m, sizeof(struct ipv4_hdr));
struct ether_hdr *eh;
	eh = (struct ether_hdr *)rte_pktmbuf_append(pkt, sizeof(struct ether_hdr));
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
	
	ether_addr_copy(&s, &eh->s_addr);
	ether_addr_copy(&d, &eh->d_addr);

	//uint64_t rand = rte_rand();
	//uint8_t *p = (uint8_t*)&rand;
	//ether_addr_copy(&ports_eth_addr[port], &ethdr->s_addr);
    	eh->ether_type = rte_be_to_cpu_16(ETHER_TYPE_IPv4);
	//rte_memcpy(eth->saddr, p, ETHER_ADDR_LEN);
	printf("ANON!\n");
        printf("the size is %i\n", rte_ctrlmbuf_len(pkt));
        printf("%s", rte_ctrlmbuf_data(pkt));
        printf("ANON2\n");
        int i = 0;
        for (i =0; i < rte_ctrlmbuf_len(pkt); i++)
        {
                printf ("%04x", *(rte_ctrlmbuf_data(pkt)+i));
        }
        printf("\nANON3\n");

	//meta->destination = pkt->port;
	meta->destination = 0;
        //if (onvm_pkt_mac_addr_swap(pkt, 0) != 0) {
        //        printf("ERROR: MAC failed to swap!\n");
       // }
	*/
	//printf ("  %i a packet received\n",meta->destination );
	//check if it is IPinIP and detach outside IP header
	//printf ("23th %02x", (unsigned char)*(rte_ctrlmbuf_data(pkt)+23));
	//if ((unsigned char)*(rte_ctrlmbuf_data(pkt)+23) == 0x04) // IPIP packet
	//{
		//we should remove the inner IP
		
	//{
	struct ether_hdr * eh;
	eh = rte_pktmbuf_mtod (pkt,struct ether_hdr*); 
	//printf("l2type %u", pkt->l2_type);

	//printf ("source addr: %u", eh->s_addr.addr_bytes[0]);
 	//printf ("destination addr0: %u", eh->d_addr.addr_bytes[0]);
	//printf ("destination addr1: %u", eh->d_addr.addr_bytes[1]);
	//printf ("destination addr2: %u", eh->d_addr.addr_bytes[2]);
	//printf ("destination addr3: %u", eh->d_addr.addr_bytes[3]);
	//printf ("destination addr4: %u", eh->d_addr.addr_bytes[4]);
	//printf ("destination addr5: %u", eh->d_addr.addr_bytes[5]);
	//if destination port is em49 (there should be a better way to do it)
	//if ((eh->d_addr.addr_bytes[4] == 194u))
	//{
	//	printf ("Gorilla");
	//}
	if ((eh->d_addr.addr_bytes[0] == 140u) & (eh->d_addr.addr_bytes[1] == 220u) 
	   && (eh->d_addr.addr_bytes[2] == 212u) && (eh->d_addr.addr_bytes[3] == 172u)
	   && (eh->d_addr.addr_bytes[4] == 194u) && (eh->d_addr.addr_bytes[5] == 16u) )  	
	{
		//printf("packet received from outside, remove ether header\n");
		// remove ethernet header
		rte_pktmbuf_adj(pkt, 14);
		struct ipv4_hdr *iph;
		iph = rte_pktmbuf_mtod (pkt,struct ipv4_hdr*);
		if (iph->next_proto_id == 0x04)
		{
			//printf("remove tunnel IP header\n");
			rte_pktmbuf_adj(pkt, 20);
		}else 
		{
			//it was not a tunnel
			////printf ("received a packet, not in tunnel, probably for core\n");
			meta->destination = 2;
			meta->action = ONVM_NF_ACTION_TONF;
			return 0;
		}
		//iph = rte_pktmbuf_mtod (pkt,struct ipv4_hdr*);
		//printf ("inner source: %u", rte_cpu_to_be_32(iph->src_addr));
		// 192.168.1.1 is 1677721640
		//printf ("inner dest: %u", rte_cpu_to_be_32(iph->dst_addr));
		meta->destination = 3;
		meta->action = ONVM_NF_ACTION_TONF;
		return 0;
		
	} else {
	// packet wants to go outside from inside
		//printf("packet wants to go outside\n");
		//ANON
      		//  printf("packet port is: %i", pkt->port);
       		meta->action = ONVM_NF_ACTION_OUT;
        	// Add IP header for the IP Tunneling
        	struct ipv4_hdr *iph;
        	iph = (struct ipv4_hdr *)rte_pktmbuf_prepend(pkt, sizeof(struct ipv4_hdr));
        	iph->time_to_live = 40;
        	iph->dst_addr = rte_be_to_cpu_32(167772161);//10.0.0.1
        	iph->src_addr = rte_be_to_cpu_32(167772162); //10.0.0.2
        	iph->version_ihl = 69; //type 4 length 5 words
        	iph->next_proto_id = 0x04; //ip in ip

        	//struct ipv4_hdr *iph;
        	//iph = (struct ipv4_hdr *)rte_pktmbuf_append(m, sizeof(struct ipv4_hdr));
       	 	struct ether_hdr *eh;
        	eh = (struct ether_hdr *)rte_pktmbuf_prepend(pkt, sizeof(struct ether_hdr));
        	//eh->ether_type = ETHER_TYPE_IPv4;
        	struct ether_addr s;
        	struct ether_addr d;
        	s.addr_bytes[0] = 0x8c;
        	s.addr_bytes[1] = 0xdc;
        	s.addr_bytes[2] = 0xd4;
        	s.addr_bytes[3] = 0xac;
        	s.addr_bytes[4] = 0xc2;
        	s.addr_bytes[5] = 0x10;

        	d.addr_bytes[0] = 0x8c;
        	d.addr_bytes[1] = 0xdc;
        	d.addr_bytes[2] = 0xd4;
        	d.addr_bytes[3] = 0xac;
        	d.addr_bytes[4] = 0xc0;
        	d.addr_bytes[5] = 0x94;
 		ether_addr_copy(&s, &eh->s_addr);
        	ether_addr_copy(&d, &eh->d_addr);

        	//uint64_t rand = rte_rand();
        	//uint8_t *p = (uint8_t*)&rand;
        	//ether_addr_copy(&ports_eth_addr[port], &ethdr->s_addr);
        	eh->ether_type = rte_be_to_cpu_16(ETHER_TYPE_IPv4);
        	//rte_memcpy(eth->saddr, p, ETHER_ADDR_LEN);
        	//printf("ANON!\n");
        	//printf("the size is %i\n", rte_ctrlmbuf_len(pkt));
        	//printf("%s", rte_ctrlmbuf_data(pkt));
        	//printf("ANON2\n");
        	//int i = 0;
        	//for (i =0; i < rte_ctrlmbuf_len(pkt); i++)
        	//{
                //	printf ("%i: %02x\n",i, (unsigned char)*(rte_ctrlmbuf_data(pkt)+i));
        	//}
        	//printf("\nANON3\n");
        	//meta->destination = pkt->port;
        	meta->destination = 0;
        	//if (onvm_pkt_mac_addr_swap(pkt, 0) != 0) {
        	//printf("ERROR: MAC failed to swap!\n");
       		// }
        	return 0;
	}
       return 0;
}


int main(int argc, char *argv[]) {
        int arg_offset;

        const char *progname = argv[0];

        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG)) < 0)
                return -1;
        argc -= arg_offset;
        argv += arg_offset;

        if (parse_app_args(argc, argv, progname) < 0)
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");

        onvm_nflib_run(nf_info, &packet_handler);
        printf("If we reach here, program is ending");
        return 0;
}
