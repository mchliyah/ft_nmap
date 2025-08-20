#include "../include/ft_nmap.h"


unsigned short csum(unsigned short *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char*)&oddbyte) = *(unsigned char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;
    return answer;
}

// Generate a random source port like nmap does
uint16_t generate_source_port() {
    return 32768 + (rand() % 28232); // Nmap's range
}

void set_ip_header(struct ip *ip, const char *src_ip, struct sockaddr_in *target) {
    ip->ip_hl = sizeof(*ip) >> 2;
    ip->ip_v = 4;
    ip->ip_tos = 0;
    ip->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
    ip->ip_id = htons(rand() & 0xFFFF);
    ip->ip_off = htons(16384);
    ip->ip_ttl = 64;
    ip->ip_p = IPPROTO_TCP;
    ip->ip_src.s_addr = inet_addr(src_ip);
    ip->ip_dst = target->sin_addr;
}

void set_tcp_header(struct tcphdr *tcp, scan_type_t target_type) {


    tcp->source = htons(43591);
	tcp->dest = htons(80); // default set to 80 thread scan will handle based on range
	tcp->seq = htonl(1105024978);
	tcp->ack_seq = 0;
	tcp->doff = sizeof(struct tcphdr) / 4;
	tcp->fin = (target_type & SCAN_FIN) ? 1 : 0;
	tcp->rst = 0;
	tcp->syn = (target_type & SCAN_SYN) ? 1 : 0;
	tcp->ack = (target_type & SCAN_ACK) ? 1 : 0;
	tcp->window = htons(14600);
	tcp->check = 0;
	tcp->urg_ptr = 0;
}

void set_psudo_header(struct pseudo_header *psh, const char *src_ip, struct sockaddr_in *target)
{
    psh->source_address = inet_addr(src_ip);
    psh->dest_address = target->sin_addr.s_addr;
    psh->placeholder = 0;
    psh->protocol = IPPROTO_TCP;
    psh->tcp_length = htons(sizeof(struct tcphdr));
}