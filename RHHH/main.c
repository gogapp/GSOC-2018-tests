/*
 * Gatekeeper - DoS protection system.
 * Copyright (C) 2016 Digirati LTDA.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <unistd.h>

#include <pcap/pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_memory.h>

#include "cycles2sec.h"
#include "gatekeeper_rhhh.h"

char errbuf[PCAP_ERRBUF_SIZE];

const char *fname = "/home/gogapp/data/equinix-nyc.dirA.20180419-140100.UTC.anon.pcap";

/* this may depend on the parameter phi */
#define BH_POOL_SIZE  1024
#define BH_CACHE_SIZE 64

#define BH_RING_SIZE  1024

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define IPVERSION4 4
#define IPVERSION6 6

static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN, },
};

extern uint64_t cycles_per_sec;

struct rte_hash *counter_ip4[NUM_V4_COUNTERS];
struct rte_hash *counter_ip6[NUM_V6_COUNTERS];

uint8_t ipver;
char ip4_src[INET_ADDRSTRLEN];
char ip4_dst[INET_ADDRSTRLEN];
char ip6_src[INET6_ADDRSTRLEN];
char ip6_dst[INET6_ADDRSTRLEN];
int num_ip4;
int num_ip6;

struct ip_key *hh_table;
int ht_size = 1024 * 1024;

/* the given percentage */
static float fPhi = 0.2;
static double epsilon = 0.25 * 1e-6;
static unsigned nb_ports;

/* report period is 30 seconds */
static uint64_t t_report_interval;
static uint64_t t_app_start;

static struct rte_ring *bh_counting_stat_ring;
static struct rte_mempool *bh_counting_stat_pool;

struct bh_counting_stat {
    struct ip_key item;
    int count;
    uint64_t time;
    unsigned int lcore_id;
};

static inline int
bh_counting_init(void)
{
    bh_counting_stat_pool = rte_mempool_create("bh_counting_stat_pool",
            BH_POOL_SIZE, sizeof(struct bh_counting_stat), BH_CACHE_SIZE,
            0, NULL, NULL, NULL, NULL, rte_socket_id(), 0);

    if (bh_counting_stat_pool == NULL)
        rte_exit(EXIT_FAILURE, "Problem getting black holing stat pool\n");

    bh_counting_stat_ring = rte_ring_create("bh_counting_stat_ring",
            BH_RING_SIZE, rte_socket_id(), RING_F_SC_DEQ);

    if (bh_counting_stat_ring == NULL)
        rte_exit(EXIT_FAILURE, "Problem getting black holing stat ring\n");

    t_report_interval = (0.01 * cycles_per_sec);

    return 0;
}

/*
 * Initialises a given port using global settings and with the rx buffers
 * coming from the mbuf_pool passed as parameter
 */
static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	int retval;
	uint16_t q;

	if (port >= rte_eth_dev_count_avail())
		return -1;

	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
			return retval;
	}

	retval  = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	struct ether_addr addr;

	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02"PRIx8" %02"PRIx8" %02"PRIx8
			" %02"PRIx8" %02"PRIx8" %02"PRIx8"\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	rte_eth_promiscuous_enable(port);

	return 0;
}

/*static int
send_stat(unsigned int lcore_id, struct ip_key item, int count)
{

	if(item.proto == ETHER_TYPE_IPv4) {
		printf("In send_stat function: lcore_id = %u item src = %u, item dst = %u count = %u\n", lcore_id, item.k.v4.src.s_addr, item.k.v4.dst.s_addr, count);
	} else if(item.proto == ETHER_TYPE_IPv6) {
		printf("In send_stat function: lcore_id = %u item src = %X, item dst = %X count = %u\n", lcore_id, item.k.v6.src.s6_addr, item.k.v6.dst.s6_addr, count);
	}
	struct bh_counting_stat *stat = NULL;
	int ret = rte_mempool_mc_get(bh_counting_stat_pool, (void **)&stat);

	if (ret == -ENOENT) {
		printf("Not enough entries in the mempool\n");
		return -1;
	}

	stat->item = item;
	stat->count = count;
	stat->time = rte_rdtsc();
	stat->lcore_id = lcore_id;

	ret = rte_ring_mp_enqueue(bh_counting_stat_ring, stat);

	if (ret == -EDQUOT) {
		printf("RING ENQUEUE ERROR: Quota exceeded. The objects have been enqueued, but the high water mark is exceeded.\n");
		rte_mempool_mp_put(bh_counting_stat_pool, stat);
		return -1;
	} else if (ret == -ENOBUFS) {
		printf("RING ENQUEUE ERROR: Quota exceeded. Not enough room in the ring to enqueue.\n");
		rte_mempool_mp_put(bh_counting_stat_pool, stat);
		return -1;
	}

	return 0;
}*/

void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
	const struct ether_header *ethernet;
	const struct ip *ip;
	const struct ip6_hdr *ip6_hdr;
	const struct tcphdr *tcp;
	const struct udphdr *udp;
	uint8_t proto;
	int i;
	
	unsigned int socket_id = rte_lcore_to_socket_id(rte_lcore_id());

	/* Extract IP information. */
	ip = (struct ip*)packet;
	ipver = ip->ip_v;
	proto = ip->ip_p;
	
	if(ipver == 4) {
		/* IPv4 type packet. */
		inet_ntop(AF_INET, &(ip->ip_src), ip4_src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ip->ip_dst), ip4_dst, INET_ADDRSTRLEN);
		struct ip_key key = {
			.proto = ETHER_TYPE_IPv4,
			.k.v4.src = ip->ip_src,
			.k.v4.dst = ip->ip_dst,
		};		
		num_ip4++;
		//printf("IP Packet: Verion = %d, Header Caplen = %d, Header Len = %d, Src = %s,  Dst = %s\n", ipver, h->caplen, h->len, ip4_src, ip4_dst);
		//space_saving(socket_id, ETHER_TYPE_IPv4, &key, counter_ip4[0]);
		rhhh_update(socket_id, &key);
		
	} else if(ipver == 6) {
		/* IPv6 type packet */
		ip6_hdr = (struct ip6_hdr*)packet;
		inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), ip6_src, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), ip6_dst, INET6_ADDRSTRLEN);
		num_ip6++;
		struct ip_key key = {
			.proto = ETHER_TYPE_IPv6,
			.k.v6.src = ip6_hdr->ip6_src,
			.k.v6.dst = ip6_hdr->ip6_dst,
		};
		//printf("IP Packet: Verion = %d, Header Caplen = %d, Header Len = %d, Src = %s,  Dst = %s\n", ipver, h->caplen, h->len, ip6_src, ip6_dst);
		//space_saving(socket_id, ETHER_TYPE_IPv6, &key, counter_ip6[0]);
		rhhh_update(socket_id, &key);	
		
	}
}

/*
 * thread that does the counting work on each lcore
 */
static  int
lcore_counting(__attribute__((unused)) void *arg)
{
	uint8_t port;
	int i, ret;	

	uint32_t pkts_to_send = 150000;
	int tot_traffic;
	uint64_t t_last_report = t_app_start;
	unsigned int socket_id = rte_lcore_to_socket_id(rte_lcore_id());  
	double prob = 1.0;
	int threshold = 450;
	
	for (port = 0; port < nb_ports; port++)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
				(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());
	/*counter_ip4[0] = create_counter_table(socket_id, ETHER_TYPE_IPv4, 0, ht_size);
	if(counter_ip4[0] != NULL)
		printf("IPv4 table created successfully!\n");
 	*/
	ret = rhhh_init(socket_id, ETHER_TYPE_IPv4, prob);
	for(i = 0; i < NUM_V4_COUNTERS; i++) {
		if(counter_ip4[i] == NULL)
			printf("Failed to create IPv4 table!\n");
	}

	/*counter_ip6[0] = create_counter_table(socket_id, ETHER_TYPE_IPv6, 1, ht_size);	
	if(counter_ip6[0] != NULL)
		printf("IPv6 table created successfully!\n");
	*/
	ret = rhhh_init(socket_id, ETHER_TYPE_IPv6, prob);
	for(i = 0; i < NUM_V6_COUNTERS; i++) {
		if(counter_ip6[i] == NULL)
			printf("Failed to create IPv6 table!\n");
	}

	struct rte_hash *bkt_v41 = create_bucket(socket_id, ETHER_TYPE_IPv4, 0);
	struct rte_hash *bkt_v42 = create_bucket(socket_id, ETHER_TYPE_IPv4, 1);	

	struct counter_bucket ct_bkt1 = {
		.proto = ETHER_TYPE_IPv4,
		.bkt_id = 0,
		.bkt.bkt_ip4 = bkt_v41,
	};

	INIT_LIST_HEAD(&ct_bkt1.list);
	list_add(&ct_bkt1.list, &bkt_head_ip4);

	struct counter_bucket ct_bkt2 = {
		.proto = ETHER_TYPE_IPv4,
		.bkt_id = 1,
		.bkt.bkt_ip4 = bkt_v42,
	};

	INIT_LIST_HEAD(&ct_bkt1.list);
	list_add(&ct_bkt2.list, &ct_bkt1.list);
	
	pcap_t *p;	
	p = pcap_open_offline(fname, errbuf);
	if(p == NULL) {
		printf("Unable to open pcap file!\n");
		return 1;
	}	
	
	int iter;
	for(iter = 0; iter < 1; iter++) {
		uint t_st = rte_rdtsc(); 
		if(pcap_loop(p, pkts_to_send, callback, NULL) < 0) {
			printf("pcap_loop() failed!\n");
			return 1; 
		}
		uint t_en = rte_rdtsc(); 

		tot_traffic = num_ip4 + num_ip6;
		printf("\nCaptured %d packets. %llu usec \n", tot_traffic, time_diff_in_us(t_en, t_st));
		
		int adjustedThreshold = threshold / NUM_V4_COUNTERS;
		//ret = rhhh1D_v4_output(threshold, socket_id);		
		for(i = 0; i < NUM_V4_COUNTERS; i++)
			SSiterate(counter_ip4[i], ETHER_TYPE_IPv4, 1);		
		//SSiterate(counter_ip4[0], ETHER_TYPE_IPv4, threshold);
		adjustedThreshold = threshold / NUM_V6_COUNTERS;
		for(i = 0; i < NUM_V6_COUNTERS; i++)
			SSiterate(counter_ip6[i], ETHER_TYPE_IPv6, 1);		
		//SSiterate(counter_ip6[0], ETHER_TYPE_IPv6, threshold);
		
		rhhh_deinit(ETHER_TYPE_IPv4);
		//destroy_counter_table(ETHER_TYPE_IPv4, 0);
		rhhh_deinit(ETHER_TYPE_IPv6);
		//destroy_counter_table(ETHER_TYPE_IPv6, 1);
		ret = rhhh_init(socket_id, ETHER_TYPE_IPv4, 1);		
		//counter_ip4[0] = create_counter_table(socket_id, ETHER_TYPE_IPv4, 0, ht_size);
		ret = rhhh_init(socket_id, ETHER_TYPE_IPv6, 1);		
		//counter_ip6[0] = create_counter_table(socket_id, ETHER_TYPE_IPv6, 1, ht_size);	
	
		num_ip4 = 0;
		num_ip6 = 0;
		tot_traffic = 0;
	}
	
	for(i = 0; i < NUM_V4_COUNTERS; i++) {
		if(counter_ip4[i]) {
			rhhh_deinit(ETHER_TYPE_IPv4);
		}
	}
	
	for(i = 0; i < NUM_V6_COUNTERS; i++) {
		if(counter_ip6[i]) {
			rhhh_deinit(ETHER_TYPE_IPv6);
		}
	}
	return 0;
}

/*static  int
lcore_combine_stat(__attribute__((unused)) void *arg)
{
	int com_tot_traffic = 0;
	uint64_t t_last_report = t_app_start;
	struct bh_counting_stat *stat;

	printf("\nCore %u combines the results. [Ctrl+C to quit]\n",
			rte_lcore_id());

	//LCL_type *lcl = LCL_Init(fPhi / 8);

	while (1) {

		uint64_t t_now = rte_rdtsc();
		sleep(1);
		printf("Core running!\n");

		
		// enter a new report period 
		// delay 10 seconds to do the results collection
		// make sure all the stat results have been received from other lcores
		//
		if (t_now - t_last_report >= (t_report_interval + t_report_interval / 3)) {
			LCL_ShowHeap(lcl);

			printf("fPhi = %f, totoal traffic = %d bytes\n", fPhi, com_tot_traffic);

			int i = 1;
			for (i = 1; i <= lcl->size; ++i) {
				if (lcl->counters[i].count > fPhi * com_tot_traffic) {
					printf("Dest: %u has estimated %d Bytes traffic!\n", lcl->counters[i].item, lcl->counters[i].count);
				}
			}

			com_tot_traffic = 0;
			t_last_report += t_report_interval;
			
			LCL_Destroy(lcl);
			lcl = LCL_Init(fPhi / 8);
		}

		if (rte_ring_dequeue(bh_counting_stat_ring, (void **)&stat) < 0) {
			usleep(5);
			continue;
		}

		if (stat->item == LCL_NULLITEM) com_tot_traffic += stat->count;
		else LCL_Update(lcl, stat->item, stat->count);

		rte_mempool_mp_put(bh_counting_stat_pool, stat);
			
	}

	return 0;
}*/

/* Main function, does initialisation and calls the per-lcore functions */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	uint8_t portid;

	/* init EAL */
	int ret = rte_eal_init(argc, argv);

	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	argc -= ret;
	argv += ret;

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
			NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* initialize all ports */
	for (portid = 0; portid < nb_ports; portid++)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8"\n",
					portid);

	cycles_to_sec_init();
	bh_counting_init();
	t_app_start = rte_rdtsc();

	rte_eal_remote_launch(lcore_counting, NULL, 1);
	
	/* call lcore_combine_stat on master core only */
	//lcore_combine_stat(NULL);

	rte_eal_mp_wait_lcore();
	return 0;
}

