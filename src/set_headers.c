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

void set_ip_header(struct iphdr *ip, const char *src_ip, struct sockaddr_in *target) {
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->id = htons(rand() & 0xFFFF);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr(src_ip);
    ip->daddr = target->sin_addr.s_addr;
    ip->check = 0;
}

void set_tcp_header(struct tcphdr *tcp, uint16_t src_port, struct sockaddr_in *target, uint32_t seq) {
    tcp->source = htons(src_port);
    tcp->dest = target->sin_port;
    tcp->seq = htonl(seq);
    tcp->ack_seq = 0;
    tcp->doff = 6;
    tcp->syn = 1;
    tcp->ack = 0;
    tcp->fin = 0;
    tcp->rst = 0;
    tcp->psh = 0;
    tcp->urg = 0;
    tcp->window = htons(1024);
    tcp->check = 0; 
    tcp->urg_ptr = 0;
}