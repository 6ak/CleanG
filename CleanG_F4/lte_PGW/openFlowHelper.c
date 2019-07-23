#include "openFlowHelper.h"
/* number of package between each print */
//static uint32_t print_delay = 10000000;
static uint32_t last_sent_seq_no = 1655891139;
static uint32_t next_ack_no = 0;
//static uint32_t counter = 0;
static uint32_t last_sent_of_trans_id = 1;
static uint32_t current_xid = 1000;
static uint16_t our_port = 38698;
static uint64_t datapath_id = 1275;
//static uint16_t packet_id = 0;
extern void sendLTE13Response( struct PgwOpLte13* op13);
extern void sendDLTE3Response( struct GwOpPlaceHolder* ph);
// The following variables are used because ONOS is not working properly and it break down packets
// in the middle. 
static uint32_t remainded_size = 0;
static char remainder_data [1500];
//////////////////////////////////////////////////////////////////


struct rte_mbuf * make_default_packet (void) {
  struct rte_mempool *pktmbuf_pool;
  struct rte_mbuf* pkt;
  struct tcp_packet* syn_packet;
  pktmbuf_pool = rte_mempool_lookup (PKTMBUF_POOL_NAME);
  if (pktmbuf_pool == NULL)
  {
    ali_debug_pprint("cannot find pooooool!!!!exit!\n");
    rte_exit (EXIT_FAILURE, "Cannot find mbuf pool!\n");
  }
  pkt = rte_pktmbuf_alloc (pktmbuf_pool);
  syn_packet = (struct tcp_packet *) rte_pktmbuf_prepend (pkt, sizeof (struct tcp_packet));


  struct ether_hdr *eh = &(syn_packet->pkt_eth_hdr);
  //eh = (struct ether_hdr *)rte_pktmbuf_prepend(pkt, sizeof(struct ether_hdr));
  //eh->ether_type = ETHER_TYPE_IPv4;
  struct ether_addr s;
  struct ether_addr d;
  // mac of p2p2
  d.addr_bytes[0] = 0x8c;
  d.addr_bytes[1] = 0xdc;
  d.addr_bytes[2] = 0xd4;
  d.addr_bytes[3] = 0xac;
  d.addr_bytes[4] = 0x6b;
  d.addr_bytes[5] = 0x20;

  s.addr_bytes[0] = 0x8c;
  s.addr_bytes[1] = 0xdc;
  s.addr_bytes[2] = 0xd4;
  s.addr_bytes[3] = 0xac;
  s.addr_bytes[4] = 0x6b;
  s.addr_bytes[5] = 0x64;

  // changed the place of source and destination
  ether_addr_copy(&d, &eh->s_addr);
  ether_addr_copy(&s, &eh->d_addr);

  eh->ether_type = rte_be_to_cpu_16(ETHER_TYPE_IPv4);

  struct ipv4_hdr *iph = &(syn_packet->pkt_ip_hdr);
  //iph = (struct ipv4_hdr *)rte_pktmbuf_prepend(pkt, sizeof(struct ipv4_hdr));
  iph->time_to_live = 50;
  iph->dst_addr = rte_be_to_cpu_32(OF_SERVER_IP);
  //iph->dst_addr = rte_be_to_cpu_32(IPv4(192,168,122,1));

  iph->src_addr = rte_be_to_cpu_32(OF_CLIENT_IP);
  iph->version_ihl = 69; //verion 4 length 5 words
  iph->next_proto_id = IPPROTO_TCP;
  //iph->packet_id = rte_be_to_cpu_16(packet_id);
  //packet_id++;

  struct tcp_hdr *tcp = &(syn_packet->pkt_tcp_hdr);
  tcp->recv_ack = rte_be_to_cpu_32(next_ack_no);
  tcp->src_port = rte_be_to_cpu_16(our_port);
  tcp->dst_port = rte_be_to_cpu_16(6653);
  // just set the syn
  tcp->tcp_flags = 2;
  // set the length to default 20
  tcp->data_off = 80;
  tcp->sent_seq = rte_be_to_cpu_32(last_sent_seq_no);
  //last_sent_seq_no++;
  tcp->rx_win = rte_be_to_cpu_16(29200);
  //setting the checksums
  //pmeta->l2_len = len(out_eth + out_ip + out_udp + vxlan + in_eth);
  //pmeta->l3_len = len(in_ip);
  //pmeta->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CSUM | PKT_TX_TCP_CKSUM;

  iph->total_length = rte_be_to_cpu_16(40);
  tcp->cksum = 0;
  iph->hdr_checksum = 0;
  tcp->cksum = rte_ipv4_udptcp_cksum (iph, tcp);
  iph->hdr_checksum =rte_ipv4_cksum(iph);
  //rte_ipv4_udptcp_cksum (     const struct ipv4_hdr *   ipv4_hdr,
  //const void *  l4_hdr
  //)

  //syn_packet->pkt_eth_hdr.ether_type = 1;
  //sm->command = packetType;

  return pkt;
}
//////////////////////////////////////////////////////////////////
// packet handler code:
int handleOfPackets (struct rte_mbuf* pkt, struct onvm_pkt_meta* meta) {
  struct ether_hdr * eh;
  //uint32_t original_packet_size = pkt->pkt_len;
  eh = rte_pktmbuf_mtod (pkt,struct ether_hdr*);
  // ali_debug_pprint ("a new packet received\n");
  if (eh->ether_type == rte_be_to_cpu_16(ETHER_TYPE_IPv4)){
    // remove ethernet header
    rte_pktmbuf_adj(pkt, 14);
    struct ipv4_hdr *iph;
    iph = rte_pktmbuf_mtod (pkt,struct ipv4_hdr*);
    if (iph->src_addr  == rte_be_to_cpu_32(OF_SERVER_IP))
    {
      if (iph->dst_addr  == rte_be_to_cpu_32(OF_CLIENT_IP))
      {
	if (iph->next_proto_id == IPPROTO_TCP) {
	  rte_pktmbuf_adj(pkt, 20);
	  struct tcp_hdr *tcp;
	  tcp = rte_pktmbuf_mtod (pkt,struct tcp_hdr*);
	  uint32_t tcp_header_size = ((tcp->data_off) >> 4) * 4;
	  uint32_t packet_data_size =  (rte_be_to_cpu_16(iph->total_length) - 20 - tcp_header_size);
	  next_ack_no = rte_be_to_cpu_32(tcp->sent_seq) + (rte_be_to_cpu_16(iph->total_length) - 20 - tcp_header_size);
	  // ali_debug_pprint ("next ack no: %u, tcp header size %u, iph total length %d, sent_seq %u\n", next_ack_no, tcp_header_size, rte_be_to_cpu_16(iph->total_length), rte_be_to_cpu_32(tcp->sent_seq));
	  //next_ack_no = 1;
	  // TODO: add some conditions here to find lost packets!
	  if (tcp->tcp_flags == 18) {
	    ali_debug_pprint ("syn ack received\n");
	    next_ack_no++;
	    struct rte_mbuf* pkt1 = make_default_packet();
	    struct tcp_packet* synack_packet = rte_pktmbuf_mtod(pkt1, struct tcp_packet*);
	    struct tcp_hdr *tcp1 = &(synack_packet->pkt_tcp_hdr);
	    struct ipv4_hdr *iph1 = &(synack_packet->pkt_ip_hdr);
	    tcp1->tcp_flags = 16;
	    // seq, for now it is handled in make default packet
	    //tcp1->sent_seq = rte_be_to_cpu_32(last_sent_seq_no);
	    // ack
	    //tcp1->recv_ack = rte_be_to_cpu_32(rte_be_to_cpu_32(tcp->sent_seq) + 1;
	    // update chksum
	    tcp1->cksum = 0;
	    iph1->hdr_checksum = 0;
	    tcp1->cksum = rte_ipv4_udptcp_cksum (iph1, tcp1);
	    iph1->hdr_checksum =rte_ipv4_cksum(iph1);
	    struct onvm_pkt_meta *pmeta;
	    pmeta = onvm_get_pkt_meta (pkt1);
	    pmeta->destination = PORT_TOWARD_OF_SERVER;
	    pmeta->action = ONVM_NF_ACTION_OUT;
	    //pkts[userCounter]->port = COMMAND_MESSAGE_PORT;
	    pkt1->hash.rss = 1;
	    onvm_nflib_return_pkt (pkt1);
	    //start sending of_hello
	    struct ofp_header* ofh;
	    struct rte_mbuf* pkt2 = make_default_packet();
	    last_sent_seq_no += 8;
	    struct tcp_packet* ofhello_packet = rte_pktmbuf_mtod(pkt2, struct tcp_packet*);
	    struct tcp_hdr *tcp2 = &(ofhello_packet->pkt_tcp_hdr);
	    struct ipv4_hdr *iph2 = &(ofhello_packet->pkt_ip_hdr);
	    ofh = (struct ofp_header*) rte_pktmbuf_append(pkt2, sizeof (struct ofp_header));
	    ofh->version = OFP_VERSION;
	    ofh->type = OFPT_HELLO;
	    ofh->length = rte_be_to_cpu_16(8);
	    ofh->xid = last_sent_of_trans_id;
	    last_sent_of_trans_id++;
	    //setting push and ack
	    tcp2->tcp_flags = 24;
	    iph2->total_length = rte_be_to_cpu_16 (48);
	    //tcp2->recv_ack = rte_be_to_cpu_32(rte_be_to_cpu_32(tcp->sent_seq) + 1);
	    tcp2->cksum = 0;                                                                  
	    iph2->hdr_checksum = 0;                                                           
	    tcp2->cksum = rte_ipv4_udptcp_cksum (iph2, tcp2);                                 
	    iph2->hdr_checksum =rte_ipv4_cksum(iph2);                                         
	    struct onvm_pkt_meta *pmeta2;                                                     
	    pmeta2 = onvm_get_pkt_meta (pkt2);                                               
	    pmeta2->destination = PORT_TOWARD_OF_SERVER;                                                        
	    pmeta2->action = ONVM_NF_ACTION_OUT;                                           
	    //pkts[userCounter]->port = COMMAND_MESSAGE_PORT;                            
	    pkt2->hash.rss = 2;                                                         
	    onvm_nflib_return_pkt (pkt2);
	    meta->action = ONVM_NF_ACTION_DROP;
	    return 0;
	  }
	  else {
	                if (rte_be_to_cpu_16(tcp->rx_win) < 30000)
			                printf ("tcp sequence number is %u, and ack number is %u last sent seq no%u window size %u\n", rte_be_to_cpu_32(tcp->sent_seq), rte_be_to_cpu_32(tcp->recv_ack), last_sent_seq_no, rte_be_to_cpu_16(tcp->rx_win));

	    rte_pktmbuf_adj(pkt, tcp_header_size);
	    struct ofp_header *ofph_in;
	    uint32_t processed_openflow_data = 0;
	    uint32_t message_handled = 0;
	    if (packet_data_size == 0) {
	      message_handled = 1;
	    }
	    if (remainded_size != 0 && packet_data_size != 0)
	    {
	      //printf ("saved data used!\n");
	      char * packet_begin = rte_pktmbuf_prepend( pkt, remainded_size);
	      memcpy (packet_begin, remainder_data, remainded_size);
	/*	FILE *fp;
		fp = fopen("dump.txt", "a");
		fprintf (fp, "\n--------------------- USSSIIING \n");
		if (pkt->next != NULL) {
		  fprintf (fp, "The next is not null!!! \n");
		}
		fprintf (fp, "ref cound is %u \n", rte_mbuf_refcnt_read(pkt));
		//fprintf (fp,"Break because of improper size open flow header and processed data!\n");
		fprintf (fp, "pkt len is %u, pkt data len %u packet data size is %u, processed is %u", pkt->pkt_len, pkt->data_len, packet_data_size, processed_openflow_data);
	        fprintf (fp, "btw, original packet size was %u\n", original_packet_size);
	        fprintf (fp, "somethign is wrong whith this while loop\n");
		fprintf (fp, "packet data size is %u and processed is %u\n", packet_data_size, processed_openflow_data);
		//fprintf (fp, "ofph_in->length is %u\n", rte_be_to_cpu_16(ofph_in->length));

		rte_pktmbuf_dump(fp, pkt, packet_data_size);
		fclose(fp);*/
		//remainded_size = rte_be_to_cpu_16(ofph_in->length);
		//remainded_size = packet_data_size - processed_openflow_data;
		//printf ("saving data for later, size is %u \n", remainded_size);
		//memcpy (remainder_data, ofph_in,remainded_size);
	      packet_data_size += remainded_size;
	      remainded_size = 0;  
	    }

	    while (packet_data_size > processed_openflow_data) {
	      ofph_in = rte_pktmbuf_mtod (pkt,struct ofp_header*);
	      /*
	      if (rte_be_to_cpu_16(ofph_in->length) == 0)
	      {
		critical_pprint ("break because of 00 size open flow header!\n");
		printf ("pkt len is %u, pkt data len %u packet data size is %u, processed is %u and ofph_in length is %u\n", pkt->pkt_len, pkt->data_len, packet_data_size, processed_openflow_data, rte_be_to_cpu_16(ofph_in->length));
	        printf ("btw, original packet size was %u\n", original_packet_size);
		critical_pprint ("somethign is wrong whith this while loop\n");
		critical_print ("packet data size is %u and processed is %u\n", packet_data_size, processed_openflow_data);
		critical_print ("ofph_in->length is %u\n", rte_be_to_cpu_16(ofph_in->length));
		FILE *fp;
		fp = fopen("dump.txt", "a");
		fprintf(fp, "\n-----------------------\n fprintf... data size \n");
	    	//fprintf (fp, "\n-----------------------\n fprintf... data size \n");
		if (pkt->next != NULL) {
		  fprintf (fp, "The next is not null!!! \n");
		}
		fprintf (fp, "ref cound is %u \n", rte_mbuf_refcnt_read(pkt));
		fprintf (fp,"Break because of improper size open flow header and processed data!\n");
		fprintf (fp, "pkt len is %u, pkt data len %u packet data size is %u, processed is %u and ofph_in length is %u\n", pkt->pkt_len, pkt->data_len, packet_data_size, processed_openflow_data, rte_be_to_cpu_16(ofph_in->length));
	        fprintf (fp, "btw, original packet size was %u\n", original_packet_size);
	        fprintf (fp, "somethign is wrong whith this while loop\n");
		fprintf (fp, "packet data size is %u and processed is %u\n", packet_data_size, processed_openflow_data);
		fprintf (fp, "ofph_in->length is %u\n", rte_be_to_cpu_16(ofph_in->length));

		rte_pktmbuf_dump(fp, pkt, packet_data_size);
		fclose(fp);
		break;
	      }*/
	      if ( rte_be_to_cpu_16(ofph_in->length) + processed_openflow_data > packet_data_size || rte_be_to_cpu_16(ofph_in->length) < 4) {
		/*
		critical_pprint ("Break because of improper size open flow header and processed data!\n");
		printf ("pkt len is %u, pkt data len %u packet data size is %u, processed is %u and ofph_in length is %u\n", pkt->pkt_len, pkt->data_len, packet_data_size, processed_openflow_data, rte_be_to_cpu_16(ofph_in->length));
	        printf ("btw, original packet size was %u\n", original_packet_size);
		critical_pprint ("somethign is wrong whith this while loop\n");
		critical_print ("packet data size is %u and processed is %u\n", packet_data_size, processed_openflow_data);
		critical_print ("ofph_in->length is %u\n", rte_be_to_cpu_16(ofph_in->length));*/
	/*	FILE *fp;
		fp = fopen("dump.txt", "a");
		fprintf (fp, "\n---------------------SAAAAAAVIIIIIIIIING \n");
		if (pkt->next != NULL) {
		  fprintf (fp, "The next is not null!!! \n");
		}
		fprintf (fp, "ref cound is %u \n", rte_mbuf_refcnt_read(pkt));
		fprintf (fp,"Break because of improper size open flow header and processed data!\n");
		fprintf (fp, "pkt len is %u, pkt data len %u packet data size is %u, processed is %u and ofph_in length is %u\n", pkt->pkt_len, pkt->data_len, packet_data_size, processed_openflow_data, rte_be_to_cpu_16(ofph_in->length));
	        fprintf (fp, "btw, original packet size was %u\n", original_packet_size);
	        fprintf (fp, "somethign is wrong whith this while loop\n");
		fprintf (fp, "packet data size is %u and processed is %u\n", packet_data_size, processed_openflow_data);
		fprintf (fp, "ofph_in->length is %u\n", rte_be_to_cpu_16(ofph_in->length));

		rte_pktmbuf_dump(fp, pkt, packet_data_size);
		fclose(fp);*/
		//remainded_size = rte_be_to_cpu_16(ofph_in->length);
		remainded_size = packet_data_size - processed_openflow_data;
		//printf ("saving data for later, size is %u \n", remainded_size);
		memcpy (remainder_data, ofph_in,remainded_size);
		break;
	      }

	      processed_openflow_data += rte_be_to_cpu_16 (ofph_in->length);
	      switch (ofph_in->type) {
		case OFPT_HELLO:
		  ali_debug_pprint ("ofpt hello\n"); 
		  //nothing needs to be done!
		  meta->action = ONVM_NF_ACTION_DROP;
		  return 0;
		  break;
		case OFPT_ERROR:
		  ali_debug_pprint ("ofpt error\n");
		  break;
		case OFPT_ECHO_REQUEST:
		  {
		    message_handled = 1;
		    ali_debug_pprint ("ofpt  echo request\n");
		    struct ofp_header* ofh;
		    struct rte_mbuf* pkt2 = make_default_packet();
		    last_sent_seq_no += 8;
		    struct tcp_packet* ofhello_packet = rte_pktmbuf_mtod(pkt2, struct tcp_packet*);
		    struct tcp_hdr *tcp2 = &(ofhello_packet->pkt_tcp_hdr);
		    struct ipv4_hdr *iph2 = &(ofhello_packet->pkt_ip_hdr);
		    ofh = (struct ofp_header*) rte_pktmbuf_append(pkt2, sizeof (struct ofp_header));
		    ofh->version = OFP_VERSION;
		    ofh->type = OFPT_ECHO_REPLY;
		    ofh->length = rte_be_to_cpu_16(8);
		    ofh->xid = ofph_in->xid;
		    //last_sent_of_trans_id++;
		    //setting push and ack
		    tcp2->tcp_flags = 24;
		    iph2->total_length = rte_be_to_cpu_16 (48);
		    //tcp2->recv_ack = rte_be_to_cpu_32(rte_be_to_cpu_32(tcp->sent_seq) + 1);
		    tcp2->cksum = 0;                                                                  
		    iph2->hdr_checksum = 0;                                                           
		    tcp2->cksum = rte_ipv4_udptcp_cksum (iph2, tcp2);                                 
		    iph2->hdr_checksum =rte_ipv4_cksum(iph2);                                         
		    struct onvm_pkt_meta *pmeta2;                                                     
		    pmeta2 = onvm_get_pkt_meta (pkt2);                                               
		    pmeta2->destination = PORT_TOWARD_OF_SERVER;                                                        
		    pmeta2->action = ONVM_NF_ACTION_OUT;                                           
		    //pkts[userCounter]->port = COMMAND_MESSAGE_PORT;                            
		    pkt2->hash.rss = 2;                                                         
		    onvm_nflib_return_pkt (pkt2);	
		  }
		  break;
		case OFPT_ECHO_REPLY:
		  ali_debug_pprint ("ofpt echo reply\n");
		  break;
		case OFPT_VENDOR:
		  {
		    message_handled = 1;
		    ali_debug_pprint ("ofpt vendor request\n");
		    //actually not vendor!! role request!
		    struct ofp_header* ofh;
		    struct rte_mbuf* pkt2 = make_default_packet();
		    uint32_t vendor_content_size = 20;
		    struct extended_vendor {
		      struct ofp_vendor_header ofvh;
		      uint32_t sub_type;
		      uint32_t role;
		    };
		    last_sent_seq_no+= vendor_content_size;
		    struct tcp_packet* ofhello_packet = rte_pktmbuf_mtod(pkt2, struct tcp_packet*);
		    struct tcp_hdr *tcp2 = &(ofhello_packet->pkt_tcp_hdr);
		    struct ipv4_hdr *iph2 = &(ofhello_packet->pkt_ip_hdr);
		    struct extended_vendor* ev;
		    struct ofp_vendor_header* ovh;
		    ev = (struct extended_vendor*) rte_pktmbuf_append(pkt2, sizeof (struct extended_vendor));  
		    ovh = &(ev->ofvh);
		    ofh = &(ovh->header);
		    ofh->version = OFP_VERSION;
		    ofh->type = OFPT_VENDOR;
		    ofh->length = rte_be_to_cpu_16(vendor_content_size);
		    ofh->xid = ofph_in->xid;
		    ovh->vendor = rte_be_to_cpu_32(0x00002320);
		    ev->sub_type = rte_be_to_cpu_32(0xb);
		    ev->role = rte_be_to_cpu_32(0x1);
		    //*(&(ovh->vendor) + 4) = 0xa;
		    //setting push and ack
		    tcp2->tcp_flags = 24;
		    iph2->total_length = rte_be_to_cpu_16 (40 + vendor_content_size);
		    //tcp2->recv_ack = rte_be_to_cpu_32(rte_be_to_cpu_32(tcp->sent_seq) + 1);
		    tcp2->cksum = 0;                                                                  
		    iph2->hdr_checksum = 0;                                                           
		    tcp2->cksum = rte_ipv4_udptcp_cksum (iph2, tcp2);                                 
		    iph2->hdr_checksum =rte_ipv4_cksum(iph2);                                         
		    struct onvm_pkt_meta *pmeta2;                                                     
		    pmeta2 = onvm_get_pkt_meta (pkt2);                                               
		    pmeta2->destination = PORT_TOWARD_OF_SERVER;                                                        
		    pmeta2->action = ONVM_NF_ACTION_OUT;                                           
		    //pkts[userCounter]->port = COMMAND_MESSAGE_PORT;                            
		    pkt2->hash.rss = 2;                                                         
		    onvm_nflib_return_pkt (pkt2);

		  }
		  break;
		case OFPT_FEATURES_REQUEST:
		  {
		    message_handled = 1;
		    ali_debug_pprint ("ofpt features request\n");
		    struct ofp_header* ofh;
		    struct rte_mbuf* pkt2 = make_default_packet();
		    last_sent_seq_no+= 32;
		    struct tcp_packet* ofhello_packet = rte_pktmbuf_mtod(pkt2, struct tcp_packet*);
		    struct tcp_hdr *tcp2 = &(ofhello_packet->pkt_tcp_hdr);
		    struct ipv4_hdr *iph2 = &(ofhello_packet->pkt_ip_hdr);
		    struct ofp_switch_features* swf;
		    swf = (struct ofp_switch_features*) rte_pktmbuf_append(pkt2, sizeof (struct ofp_switch_features));  
		    ofh = &(swf->header);
		    ofh->version = OFP_VERSION;
		    ofh->type = OFPT_FEATURES_REPLY;
		    ofh->length = rte_be_to_cpu_16(32);
		    ofh->xid = ofph_in->xid;
		    swf->datapath_id = datapath_id;
		    swf->n_buffers = rte_be_to_cpu_32(1);
		    swf->n_tables = rte_be_to_cpu_32(1);
		    swf->pad[0] = 0;
		    swf->pad[1] = 0;
		    swf->pad[2] = 0;
		    swf->capabilities = 0;
		    swf->actions = 0; 

		    //setting push and ack
		    tcp2->tcp_flags = 24;
		    iph2->total_length = rte_be_to_cpu_16 (40 + 32);
		    //tcp2->recv_ack = rte_be_to_cpu_32(rte_be_to_cpu_32(tcp->sent_seq) + 1);
		    tcp2->cksum = 0;                                                                  
		    iph2->hdr_checksum = 0;                                                           
		    tcp2->cksum = rte_ipv4_udptcp_cksum (iph2, tcp2);                                 
		    iph2->hdr_checksum =rte_ipv4_cksum(iph2);                                         
		    struct onvm_pkt_meta *pmeta2;                                                     
		    pmeta2 = onvm_get_pkt_meta (pkt2);                                               
		    pmeta2->destination = PORT_TOWARD_OF_SERVER;                                                        
		    pmeta2->action = ONVM_NF_ACTION_OUT;                                           
		    //pkts[userCounter]->port = COMMAND_MESSAGE_PORT;                            
		    pkt2->hash.rss = 2;                                                         
		    onvm_nflib_return_pkt (pkt2);
		  }
		  break;
		case OFPT_FEATURES_REPLY:
		  ali_debug_pprint ("ofpt features reply\n");
		  break;
		case OFPT_GET_CONFIG_REQUEST:
		  {
		    message_handled = 1;
		    ali_debug_pprint ("ofpt get config request\n");
		    struct ofp_header* ofh;
		    struct rte_mbuf* pkt2 = make_default_packet();
		    last_sent_seq_no+= 12;
		    struct tcp_packet* ofhello_packet = rte_pktmbuf_mtod(pkt2, struct tcp_packet*);
		    struct tcp_hdr *tcp2 = &(ofhello_packet->pkt_tcp_hdr);
		    struct ipv4_hdr *iph2 = &(ofhello_packet->pkt_ip_hdr);
		    struct ofp_get_config_response {
		      struct ofp_header header;
		      uint16_t flags;
		      uint16_t max_packetin_size;
		    };
		    struct ofp_get_config_response* gcr;
		    gcr = (struct ofp_get_config_response*) rte_pktmbuf_append(pkt2, sizeof (struct ofp_get_config_response));  
		    ofh = &(gcr->header);
		    ofh->version = OFP_VERSION;
		    ofh->type = OFPT_GET_CONFIG_REPLY;
		    ofh->length = rte_be_to_cpu_16(12);
		    ofh->xid = ofph_in->xid;
		    gcr->flags = 0;
		    gcr->max_packetin_size = 0xFFu;
		    //setting push and ack
		    tcp2->tcp_flags = 24;
		    iph2->total_length = rte_be_to_cpu_16 (40 + 12);
		    //tcp2->recv_ack = rte_be_to_cpu_32(rte_be_to_cpu_32(tcp->sent_seq) + 1);
		    tcp2->cksum = 0;                                                                  
		    iph2->hdr_checksum = 0;                                                           
		    tcp2->cksum = rte_ipv4_udptcp_cksum (iph2, tcp2);                                 
		    iph2->hdr_checksum =rte_ipv4_cksum(iph2);                                         
		    struct onvm_pkt_meta *pmeta2;                                                     
		    pmeta2 = onvm_get_pkt_meta (pkt2);                                               
		    pmeta2->destination = PORT_TOWARD_OF_SERVER;                                                        
		    pmeta2->action = ONVM_NF_ACTION_OUT;                                           
		    //pkts[userCounter]->port = COMMAND_MESSAGE_PORT;                            
		    pkt2->hash.rss = 2;                                                         
		    onvm_nflib_return_pkt (pkt2);
		  }
		  break;
		case OFPT_GET_CONFIG_REPLY:
		  ali_debug_pprint ("ofpt get config reply\n");
		  break;
		case OFPT_SET_CONFIG:
		  ali_debug_pprint ("ofpt set config\n");
		  break;
		case OFPT_PACKET_OUT:
		  ali_debug_pprint ("ofpt packet out\n");
		  uint32_t* messageCode2 = rte_pktmbuf_mtod_offset (pkt, uint32_t*, 26);
		  if (*messageCode2 == PGW_OP_LTE13_BACK_CODE){
		    ali_debug_pprint ("op lte 13 is received\n");
		    struct PgwOpLte13 *op13 = rte_pktmbuf_mtod_offset (pkt, struct PgwOpLte13*, 26);
		    sendLTE13Response(op13);
		  } else if (*messageCode2 == PGW_OP_DETACH_BACK_CODE){
		    ali_debug_pprint ("op dlte 3 is received\n");
		    struct GwOpPlaceHolder *ph = rte_pktmbuf_mtod_offset (pkt, struct GwOpPlaceHolder*, 26);
		    sendDLTE3Response(ph);
		  }


		  break;
		case OFPT_PACKET_IN:
		  ali_debug_pprint ("ofpt packet in\n");
		  break;
		case OFPT_STATS_REQUEST:
		  {
		    struct ofp_stats_message {
		      struct ofp_header header;
		      uint16_t stat_types;
		      uint16_t flags;
		    };
		    struct ofp_stats_message* stats_header;
		    stats_header = rte_pktmbuf_mtod (pkt,struct ofp_stats_message*);
		    switch (rte_be_to_cpu_16(stats_header->stat_types)) {
		      case OFPST_DESC:
			{
			  ali_debug_pprint ("desc stats request\n"); 
			  message_handled = 1;
			  ali_debug_pprint ("ofpt stat request\n");
			  struct ofp_header* ofh;
			  struct rte_mbuf* pkt2 = make_default_packet();
			  last_sent_seq_no+= 1068;
			  struct tcp_packet* ofhello_packet = rte_pktmbuf_mtod(pkt2, struct tcp_packet*);
			  struct tcp_hdr *tcp2 = &(ofhello_packet->pkt_tcp_hdr);
			  struct ipv4_hdr *iph2 = &(ofhello_packet->pkt_ip_hdr);
			  struct ofp_stats_response {
			    struct ofp_header header;
			    uint16_t type;
			    uint16_t flags;
			    struct ofp_desc_stats stats;
			  };
			  struct ofp_stats_response* osr;
			  osr = (struct ofp_stats_response*) rte_pktmbuf_append(pkt2, sizeof (struct ofp_stats_response));  
			  ofh = &(osr->header);
			  ofh->version = OFP_VERSION;
			  ofh->type = OFPT_STATS_REPLY;
			  ofh->length = rte_be_to_cpu_16(1068);
			  ofh->xid = ofph_in->xid;
			  osr->type = OFPST_DESC;
			  osr->flags = 0;
			  strcpy(osr->stats.mfr_desc, "Nicira, Inc.");
			  strcpy(osr->stats.hw_desc, "Open vSwitch");
			  strcpy(osr->stats.sw_desc, "2.0.2");		    
			  strcpy(osr->stats.serial_num, "None");
			  strcpy(osr->stats.dp_desc, "None");
			  //setting push and ack
			  tcp2->tcp_flags = 24;
			  iph2->total_length = rte_be_to_cpu_16 (40 + 1068);
			  //tcp2->recv_ack = rte_be_to_cpu_32(rte_be_to_cpu_32(tcp->sent_seq) + 1);
			  tcp2->cksum = 0;                                                                  
			  iph2->hdr_checksum = 0;                                                           
			  tcp2->cksum = rte_ipv4_udptcp_cksum (iph2, tcp2);                                 
			  iph2->hdr_checksum =rte_ipv4_cksum(iph2);                                         
			  struct onvm_pkt_meta *pmeta2;                                                     
			  pmeta2 = onvm_get_pkt_meta (pkt2);                                               
			  pmeta2->destination = PORT_TOWARD_OF_SERVER;                                                        
			  pmeta2->action = ONVM_NF_ACTION_OUT;                                           
			  //pkts[userCounter]->port = COMMAND_MESSAGE_PORT;                            
			  pkt2->hash.rss = 2;                                                         
			  onvm_nflib_return_pkt (pkt2);

			}
			break;
		      case OFPST_FLOW:
			ali_debug_pprint ("flow stats request\n");
			break;
		      case OFPST_AGGREGATE:
			ali_debug_pprint ("aggregate stats request\n");
			break;
		      case OFPST_TABLE:
			ali_debug_pprint("table stats request\n");
			break;
		      case OFPST_PORT:
			ali_debug_pprint ("port stats request\n");
			break;
		      case OFPST_QUEUE:
			ali_debug_pprint ("queue stats request\n");
			break;
		      case OFPST_VENDOR:
			ali_debug_pprint ("vendor stats request\n");
			break;
		      default:
			ali_debug_pprint ("unknown stats request!!\n");
			ali_debug_print ("type is %u: \n",stats_header->stat_types);
			ali_debug_print ("the flag is %u \n",stats_header->flags);
		    }// stats case switch


		  }
		  break;
		case OFPT_BARRIER_REQUEST:
		  {
		    message_handled = 1;
		    ali_debug_pprint ("ofpt barrier request\n");
		    struct ofp_header* ofh;
		    struct rte_mbuf* pkt2 = make_default_packet();
		    last_sent_seq_no += 8;
		    struct tcp_packet* ofhello_packet = rte_pktmbuf_mtod(pkt2, struct tcp_packet*);
		    struct tcp_hdr *tcp2 = &(ofhello_packet->pkt_tcp_hdr);
		    struct ipv4_hdr *iph2 = &(ofhello_packet->pkt_ip_hdr);
		    ofh = (struct ofp_header*) rte_pktmbuf_append(pkt2, sizeof (struct ofp_header));
		    ofh->version = OFP_VERSION;
		    ofh->type = OFPT_BARRIER_REPLY;
		    ofh->length = rte_be_to_cpu_16(8);
		    ofh->xid = ofph_in->xid;
		    //last_sent_of_trans_id++;
		    //setting push and ack
		    tcp2->tcp_flags = 24;
		    iph2->total_length = rte_be_to_cpu_16 (48);
		    //tcp2->recv_ack = rte_be_to_cpu_32(rte_be_to_cpu_32(tcp->sent_seq) + 1);
		    tcp2->cksum = 0;                                                                  
		    iph2->hdr_checksum = 0;                                                           
		    tcp2->cksum = rte_ipv4_udptcp_cksum (iph2, tcp2);                                 
		    iph2->hdr_checksum =rte_ipv4_cksum(iph2);                                         
		    struct onvm_pkt_meta *pmeta2;                                                     
		    pmeta2 = onvm_get_pkt_meta (pkt2);                                               
		    pmeta2->destination = PORT_TOWARD_OF_SERVER;                                                        
		    pmeta2->action = ONVM_NF_ACTION_OUT;                                           
		    //pkts[userCounter]->port = COMMAND_MESSAGE_PORT;                            
		    pkt2->hash.rss = 2;                                                         
		    onvm_nflib_return_pkt (pkt2);	
		  }
		  break;
		default:
		  ali_debug_pprint ("Unknown openflow message!\n");

	      }//switch
	      rte_pktmbuf_adj(pkt, rte_be_to_cpu_16 (ofph_in->length));

	    }//while
	    if (message_handled == 0 ) {
	      //ali_debug_pprint ("Just sending tcp ack\n");
	      //struct ofp_header* ofh;
	      struct rte_mbuf* pkt2 = make_default_packet();
	      last_sent_seq_no += 0;
	      struct tcp_packet* ofhello_packet = rte_pktmbuf_mtod(pkt2, struct tcp_packet*);
	      struct tcp_hdr *tcp2 = &(ofhello_packet->pkt_tcp_hdr);
	      struct ipv4_hdr *iph2 = &(ofhello_packet->pkt_ip_hdr);
	      //ofh = (struct ofp_header*) rte_pktmbuf_append(pkt2, sizeof (struct ofp_header));
	      //ofh->version = OFP_VERSION;
	      //ofh->type = OFPT_BARRIER_REPLY;
	      //ofh->length = rte_be_to_cpu_16(8);
	      //ofh->xid = ofph_in->xid;
	      //last_sent_of_trans_id++;
	      //setting push and ack
	      tcp2->tcp_flags = 24;
	      iph2->total_length = rte_be_to_cpu_16 (40);
	      //tcp2->recv_ack = rte_be_to_cpu_32(rte_be_to_cpu_32(tcp->sent_seq) + 1);
	      tcp2->cksum = 0;                                                                  
	      iph2->hdr_checksum = 0;                                                           
	      tcp2->cksum = rte_ipv4_udptcp_cksum (iph2, tcp2);                                 
	      iph2->hdr_checksum =rte_ipv4_cksum(iph2);                                         
	      struct onvm_pkt_meta *pmeta2;                                                     
	      pmeta2 = onvm_get_pkt_meta (pkt2);                                               
	      pmeta2->destination = PORT_TOWARD_OF_SERVER;                                                        
	      pmeta2->action = ONVM_NF_ACTION_OUT;                                           
	      //pkts[userCounter]->port = COMMAND_MESSAGE_PORT;                            
	      pkt2->hash.rss = 2;                                                         
	      onvm_nflib_return_pkt (pkt2);	
	    }
	    // just random condition to send a packet_in to test packet_in messages
	    /* if (counter == 30)
	       {
	       ali_debug_pprint ("Sending the packet in\n");
	       struct ofp_header* ofh;
	       struct rte_mbuf* pkt2 = make_default_packet();
	       char data_to_send[256] = "ABCDEFGHIJKLMNOPQRTSTUVWXYZ";
	       uint32_t packet_in_total_size = 8 + 10 + 256;
	       last_sent_seq_no+= packet_in_total_size;
	       struct tcp_packet* ofhello_packet = rte_pktmbuf_mtod(pkt2, struct tcp_packet*);
	       struct tcp_hdr *tcp2 = &(ofhello_packet->pkt_tcp_hdr);
	       struct ipv4_hdr *iph2 = &(ofhello_packet->pkt_ip_hdr);
	       struct ofp_packet_in* opi;
	       opi = (struct ofp_packet_in*) rte_pktmbuf_append(pkt2, sizeof (struct ofp_packet_in));  
	       ofh = &(opi->header);
	       ofh->version = OFP_VERSION;
	       ofh->type = OFPT_PACKET_IN;
	       ofh->length = rte_be_to_cpu_16(packet_in_total_size);
	    //TODO: this xid should be random.
	    ofh->xid = 1234;
	    opi->buffer_id = 4567;
	    opi->total_len = 256;
	    opi->in_port = 1;
	    opi->reason = OFPR_NO_MATCH;
	    opi->pad = 0;
	    char* data_part = (char *) rte_pktmbuf_append(pkt2, 256);
	    strcpy(data_part, data_to_send);

	    //setting push and ack
	    tcp2->tcp_flags = 24;
	    iph2->total_length = rte_be_to_cpu_16 (40 + packet_in_total_size);
	    //tcp2->recv_ack = rte_be_to_cpu_32(rte_be_to_cpu_32(tcp->sent_seq) + 1);
	    tcp2->cksum = 0;                                                                  
	    iph2->hdr_checksum = 0;                                                           
	    tcp2->cksum = rte_ipv4_udptcp_cksum (iph2, tcp2);                                 
	    iph2->hdr_checksum =rte_ipv4_cksum(iph2);                                         
	    struct onvm_pkt_meta *pmeta2;                                                     
	    pmeta2 = onvm_get_pkt_meta (pkt2);                                               
	    pmeta2->destination = PORT_TOWARD_OF_SERVER;                                                        
	    pmeta2->action = ONVM_NF_ACTION_OUT;                                           
	    //pkts[userCounter]->port = COMMAND_MESSAGE_PORT;                            
	    pkt2->hash.rss = 2;                                                         
	    onvm_nflib_return_pkt (pkt2);

	    }*/
	    meta->action = ONVM_NF_ACTION_DROP;
	    return 0;
	  }
	}
	else {
	  ali_debug_pprint ("ipv4 packet received from controller is not tcp\n");
	}
      }
      else {
	ali_debug_pprint ("ipv4 packet received from controller but it is not destined to us\n");
      }
    }
    else {
      ali_debug_pprint ("ipv4 packet received from some one but controller\n");
    }
  }
  else {
    ali_debug_pprint ("Non ipv4 packet received!\n");
  }

  meta->action = ONVM_NF_ACTION_DROP;
  return 0;
} // handle openflow function
//////////////////////////////////////////////////////////////////
// initialization code

void makeOfConnection (void) {
  struct rte_mbuf *pkt= make_default_packet();
  last_sent_seq_no++;
  struct onvm_pkt_meta *pmeta;
  pmeta = onvm_get_pkt_meta (pkt);
  pmeta->destination = PORT_TOWARD_OF_SERVER;
  pmeta->action = ONVM_NF_ACTION_OUT;
  //pkts[userCounter]->port = COMMAND_MESSAGE_PORT;
  pkt->hash.rss = 1;
  onvm_nflib_return_pkt (pkt);
}

void sendPacketIn( void* data_to_send, uint16_t data_size) {
  ali_debug_pprint ("Sending the packet in\n");
  struct ofp_header* ofh;
  struct rte_mbuf* pkt2 = make_default_packet();
  //char data_to_send[256] = "ABCDEFGHIJKLMNOPQRTSTUVWXYZ";
  uint32_t packet_in_total_size = 8 + 10 + data_size+2;
  last_sent_seq_no+= packet_in_total_size;
  struct tcp_packet* ofhello_packet = rte_pktmbuf_mtod(pkt2, struct tcp_packet*);
  struct tcp_hdr *tcp2 = &(ofhello_packet->pkt_tcp_hdr);
  struct ipv4_hdr *iph2 = &(ofhello_packet->pkt_ip_hdr);
  struct ofp_packet_in* opi;
  opi = (struct ofp_packet_in*) rte_pktmbuf_append(pkt2, sizeof (struct ofp_packet_in));
  ofh = &(opi->header);
  ofh->version = OFP_VERSION;
  ofh->type = OFPT_PACKET_IN;
  ofh->length = rte_be_to_cpu_16(packet_in_total_size);
  //TODO: this xid should be random.
  ofh->xid = current_xid;
  current_xid++;
  opi->buffer_id = 0xffffffff;
  opi->total_len = rte_be_to_cpu_16(data_size);
  opi->in_port = 1;
  opi->reason = OFPR_NO_MATCH;
  opi->pad = 0;
  char* data_part = (char *) rte_pktmbuf_append(pkt2, data_size);
  //strcpy(data_part, data_to_send);
  memcpy(data_part, data_to_send, data_size);

  //setting push and ack
  tcp2->tcp_flags = 24;
  iph2->total_length = rte_be_to_cpu_16 (40 + packet_in_total_size);
  //tcp2->recv_ack = rte_be_to_cpu_32(rte_be_to_cpu_32(tcp->sent_seq) + 1);
  tcp2->cksum = 0;
  iph2->hdr_checksum = 0;
  tcp2->cksum = rte_ipv4_udptcp_cksum (iph2, tcp2);
  iph2->hdr_checksum =rte_ipv4_cksum(iph2);
  struct onvm_pkt_meta *pmeta2;
  pmeta2 = onvm_get_pkt_meta (pkt2);
  pmeta2->destination = PORT_TOWARD_OF_SERVER;
  pmeta2->action = ONVM_NF_ACTION_OUT;
  //pkts[userCounter]->port = COMMAND_MESSAGE_PORT;
  pkt2->hash.rss = 2;
  onvm_nflib_return_pkt (pkt2);
}

