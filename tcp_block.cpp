#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "libnet-headers.h"
#include <stdlib.h>

const char* message = "blocked!!!";
char* pattern;
uint8_t my_mac[6];

void Usage() {
  printf("syntax: tcp_block <interface> <pattern>\n");
  printf("sample: tcp_block wlan0 \"Host: test.gilgil.net\"\n");
}

struct pseudo_header{
	struct in_addr s_addr;
	struct in_addr d_addr;
	uint8_t zero = 0;
	uint8_t ip_proto;
	uint16_t tcp_len;
};

uint16_t calc_checksum(uint16_t checksum, uint16_t* buf, int size){
	checksum = 0;

	while(size >1) { 
		checksum += *buf++;
		size -= sizeof(uint16_t);
	} 
	if(size) checksum += *(uint16_t*)buf;
	checksum = (checksum >> 16) + (checksum & 0xffff); 
	checksum += (checksum >>16); 
	checksum = ~checksum;
}


int make_rst_packet(uint8_t* packet, uint32_t seq, uint32_t ack){
	struct libnet_ethernet_hdr* e_hdr = (struct libnet_ethernet_hdr*) packet;
	struct libnet_ipv4_hdr* ip_hdr=(struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
	struct libnet_tcp_hdr* t_hdr=(struct libnet_tcp_hdr *)(packet+ sizeof(struct libnet_ethernet_hdr)+ip_hdr->ip_hl*4);
	struct pseudo_header* ps_hdr;

	ps_hdr->s_addr = ip_hdr->ip_src;
	ps_hdr->d_addr = ip_hdr->ip_dst;
	ps_hdr->ip_proto = ip_hdr->ip_p;
	ps_hdr->tcp_len = t_hdr->th_off*4;

	unsigned int tcp_data_size = sizeof(struct pseudo_header) + t_hdr->th_off*4;
	uint16_t* tcp_checksum_buf = (uint16_t *)malloc(tcp_data_size);
	memcpy(tcp_checksum_buf, ps_hdr, sizeof(struct pseudo_header));
	memcpy(tcp_checksum_buf+sizeof(struct pseudo_header), t_hdr, t_hdr->th_off*4);


	for(int i=0;i<6;i++)
		e_hdr->ether_shost[i]=my_mac[i];
	ip_hdr->ip_tos=0x44;
	ip_hdr->ip_len=htons(ip_hdr->ip_hl*4+t_hdr->th_off*4);
	ip_hdr->ip_ttl=0xff;
	ip_hdr->ip_sum=0;
	calc_checksum(ip_hdr->ip_sum, (uint16_t *)ip_hdr, ip_hdr->ip_hl*4);

	t_hdr->th_seq=seq;
	t_hdr->th_ack=ack;
	t_hdr->th_flags&=0;
	t_hdr->th_flags|=TH_RST;
	t_hdr->th_flags|=TH_ACK;
	t_hdr->th_win=0;
	t_hdr->th_sum=0;
	t_hdr->th_urp=0;
	calc_checksum(t_hdr->th_sum, tcp_checksum_buf, tcp_data_size);
}

int make_fin_packet(uint8_t* packet, uint32_t seq, uint32_t ack){
	struct libnet_ethernet_hdr* e_hdr=(struct libnet_ethernet_hdr *)packet;
	struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr *)(packet +sizeof(struct libnet_ethernet_hdr));
	struct libnet_tcp_hdr* t_hdr=(struct libnet_tcp_hdr *)(packet+sizeof(struct libnet_ethernet_hdr)+ip_hdr->ip_hl*4);
	struct pseudo_header* ps_hdr;

	uint8_t* data_ptr = (uint8_t*)t_hdr + t_hdr->th_off*4;

	for(int i=0;i<6;i++)
		e_hdr->ether_dhost[i]=e_hdr->ether_shost[i];
	for(int i=0;i<6;i++)
		e_hdr->ether_shost[i]=my_mac[i];
	
	uint32_t tmp_ip = ip_hdr->ip_dst.s_addr;
	ip_hdr->ip_dst.s_addr=ip_hdr->ip_src.s_addr;
	ip_hdr->ip_src.s_addr=tmp_ip;
	ip_hdr->ip_tos=0x44;
	ip_hdr->ip_len=htons(ip_hdr->ip_hl*4+t_hdr->th_off*4+8);
	ip_hdr->ip_ttl=0xff;
	ip_hdr->ip_sum=0;
	
	uint16_t tmp_port=t_hdr->th_dport;
	t_hdr->th_dport=t_hdr->th_sport;
	t_hdr->th_sport=tmp_port;
	t_hdr->th_seq=seq;
	t_hdr->th_ack=ack;
	t_hdr->th_flags&=0;
	t_hdr->th_flags|=TH_FIN;
	t_hdr->th_flags|=TH_ACK;
	t_hdr->th_win=0;
	t_hdr->th_sum=0;
	t_hdr->th_urp=0;
	strncpy((char*)data_ptr, (char*)message, 8);
}

int tcp_block(uint8_t* packet, uint32_t seq, uint32_t ack, uint32_t header_len, uint32_t data_len, pcap_t* handle){
	uint8_t fd_packet[1024] = {0,}, bk_packet[1024] = {0,};
	memcpy(fd_packet, packet, 1024);
	memcpy(bk_packet, packet, 1024);
	make_rst_packet(fd_packet, htonl(ntohl(seq)+data_len), ack);
	make_fin_packet(bk_packet, ack, htonl(ntohl(seq)+data_len));
	pcap_inject(handle, fd_packet, header_len);
	pcap_inject(handle, bk_packet, header_len);
}

int packet_chk(uint8_t* packet, pcap_t* handle){
	struct libnet_ethernet_hdr* e_hdr = (struct libnet_ethernet_hdr*) packet;
	if (e_hdr -> ether_type != htons(ETHERTYPE_ARP)) return 0;

	struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(e_hdr+1);
	int ip_hlen = ip_hdr->ip_hl*4;
	if(ip_hdr->ip_p != IPPROTO_TCP)
		return 0;

	struct libnet_tcp_hdr* t_hdr = (struct libnet_tcp_hdr*)((uint8_t*)ip_hdr + ip_hlen);
	int tcp_hlen = t_hdr->th_off*4;
	uint8_t* data_ptr = (uint8_t*)t_hdr + t_hdr->th_off*4;
	uint32_t header_len = sizeof(struct libnet_ethernet_hdr) + ip_hlen + tcp_hlen;
	uint32_t data_len=(ntohs(ip_hdr->ip_len)-(ip_hlen+tcp_hlen));
	uint32_t seq=t_hdr->th_seq;
	uint32_t ack=t_hdr->th_ack;
	
	if(data_len < 0) {
		printf("No TCP Data!\n");
		return 0;
	}

	if(data_len < strlen(pattern)) return 0; //Not match with pattern

	for(int i=0;i<data_len - strlen(pattern);i++)
		if(!strncmp((char*)data_ptr, pattern, strlen(pattern))) tcp_block(packet, seq, ack, header_len, data_len, handle);	
}

int main(int argc, char * argv[]){
	if(argc != 3){
		Usage();
		return -1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	char* dev = argv[1];
	pattern = argv[2];

	pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1,errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	struct ifreq ifrq;
	int soc = socket(AF_INET, SOCK_DGRAM, 0);
	strcpy(ifrq.ifr_name, dev);
	ioctl(soc,SIOCGIFHWADDR, &ifrq);
	for (int i=0; i<6; i++)
		my_mac[i] = ifrq.ifr_hwaddr.sa_data[i];

	while (true) {
  		struct pcap_pkthdr* header;
  		const u_char* packet;
    	int res = pcap_next_ex(handle, &header, &packet);
    	if (res == 0) 
    		continue;
    	if (res == -1 || res == -2){
  			pcap_close(handle);
  			return 0;
    	}
    	packet_chk((uint8_t*)packet, handle);  	
  }
  return 0;
}
