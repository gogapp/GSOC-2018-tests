#include <bits/stdc++.h>
using namespace std;

#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/time.h>

char errbuf[PCAP_ERRBUF_SIZE];

const char *fname = "/home/gogapp/data/equinix-nyc.dirA.20180419-140100.UTC.anon.pcap";

uint8_t ipver;
char ip4_src[INET_ADDRSTRLEN];
char ip4_dst[INET_ADDRSTRLEN];
char ip6_src[INET6_ADDRSTRLEN];
char ip6_dst[INET6_ADDRSTRLEN];
uint16_t src_port;
uint16_t dst_port;
int priority_ip4;
int priority_ip6;
FILE *fp;

#define ETHER_TYPE_IPv4 0x0800
#define ETHER_TYPE_IPv6 0x86DD

//void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *packet);

#define pss pair<string, string>

map <pss, int> cnt_ip4;
map <pss, int> cnt_ip6;

int mx4, mx6;

void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
	const struct ether_header *ethernet;
	const struct ip *ip;
	const struct ip6_hdr *ip6_hdr;
	const struct tcphdr *tcp;
	const struct udphdr *udp;
	uint8_t proto;
	int i;
	
	/* Extract IP information. */
	ip = (struct ip*)packet;
	ipver = ip->ip_v;
	proto = ip->ip_p;
	//printf("%d  ", proto);

	if(ipver == 4) {
		/* IPv4 type packet. */
		inet_ntop(AF_INET, &(ip->ip_src), ip4_src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ip->ip_dst), ip4_dst, INET_ADDRSTRLEN);
		string src = "", dst = "";
		for(int i = 0; i < INET_ADDRSTRLEN; i++) {
			src = src + ip4_src[i];
			dst = dst + ip4_dst[i];
		}	
		//cout << src << ' ' << dst << endl;	
		pss key = make_pair(src, dst);		
		cnt_ip4[key]++;
	} else if(ipver == 6) {
		/* IPv6 type packet */
		ip6_hdr = (struct ip6_hdr*)packet;
		inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), ip6_src, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), ip6_dst, INET6_ADDRSTRLEN);
		string src = "", dst = "";
		for(int i = 0; i < INET6_ADDRSTRLEN; i++) {
			src = src + ip6_src[i];
			dst = dst + ip6_dst[i];
		}
		//cout << src << ' ' << dst << endl;
		pss key = make_pair(src, dst);
		cnt_ip6[key]++;
	}
}

int main(void)
{
	int num_of_packets = 150000;
	int threshold = 450; 	
	int num_v4 = 0, num_v6 = 0;	

	pcap_t *p;	
	p = pcap_open_offline(fname, errbuf);
	if(p == NULL) {
		printf("Unable to open pcap file!\n");
		return 1;
	}		
	
	if(pcap_loop(p, num_of_packets, callback, NULL) < 0) {
		printf("pcap_loop() failed!\n");
		return 1; 
	}
	cout << " Printing IP4 Heavy Hitters... " << endl;
	for(map<pss, int>:: iterator it = cnt_ip4.begin(); it != cnt_ip4.end(); it++){
		if(it->second >= threshold) {			
			cout << "Src = " << it->first.first << ' '  << "Dst = " << it->first.second << endl;
			num_v4++;
		}
	}
	cout << "Num of V4 HH = " << num_v4 << endl;
	cout << "Printing IPv6 Heavy Hitters... " << endl;	
	for(map<pss, int>:: iterator it = cnt_ip6.begin(); it != cnt_ip6.end(); it++){
		if(it->second >= threshold) {			
			cout << "Src = " << it->first.first << ' '  << "Dst = " << it->first.second << endl;
			num_v6++;
		}
	}
	cout << " Num of V6 HH = " << num_v6 << endl;
	return 0;
}


