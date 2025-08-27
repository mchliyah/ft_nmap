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
    return 32768 + (rand() % 28232);
}


uint16_t calculate_tcp_checksum(struct ip *ip, struct tcphdr *tcp, uint8_t *options, int options_len) {
    struct {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t tcp_len;
    } pseudo_header;
    
    // Fill pseudo header
    pseudo_header.src = ip->ip_src.s_addr;
    pseudo_header.dst = ip->ip_dst.s_addr;
    pseudo_header.zero = 0;
    pseudo_header.proto = IPPROTO_TCP;
    pseudo_header.tcp_len = htons(sizeof(struct tcphdr) + options_len);
    
    // Calculate total length for checksum calculation
    int total_len = sizeof(pseudo_header) + sizeof(struct tcphdr) + options_len;
    char *buf = malloc(total_len);
    
    // Copy pseudo header, TCP header, and options to buffer
    memcpy(buf, &pseudo_header, sizeof(pseudo_header));
    memcpy(buf + sizeof(pseudo_header), tcp, sizeof(struct tcphdr));
    memcpy(buf + sizeof(pseudo_header) + sizeof(struct tcphdr), options, options_len);
    
    // Calculate checksum
    uint16_t checksum = csum((unsigned short *)buf, total_len);
    
    free(buf);
    return checksum;
}


void set_ip_header(struct ip *ip, const char *src_ip, struct sockaddr_in *target) {
    ip->ip_hl = 5; // Header length in 32-bit words (5*4=20 bytes) i've been getting 12024
    ip->ip_v = 4;
    ip->ip_tos = 0;
    ip->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + 4);
    ip->ip_id = htons(rand() & 0xFFFF);
    ip->ip_off = 0;
    ip->ip_ttl = 64;
    ip->ip_p = IPPROTO_TCP;
    ip->ip_src.s_addr = inet_addr(src_ip);
    ip->ip_dst = target->sin_addr;
    ip->ip_sum = 0;
}

void set_tcp_header(struct tcphdr *tcp, scan_type target_type) {

    //print (target_type & SCAN_SYN) (target_type & SCAN_ACK) ...
    tcp->th_sport = htons(generate_source_port());
    tcp->th_dport = htons(80);
    tcp->th_seq = htonl(rand());
    tcp->th_ack = 0;
    tcp->th_off = 6;
    tcp->th_win = htons(1024);
    tcp->th_urp = 0;
    tcp->th_sum = 0;
    tcp->th_flags = 0;  // Initialize flags field to 0
    if (target_type & SCAN_SYN) {
        tcp->th_flags |= TH_SYN;
    }
    if (target_type & SCAN_ACK) {
        tcp->th_flags |= TH_ACK;
    }
    if (target_type & SCAN_FIN) {
        tcp->th_flags |= TH_FIN;
    }
    if (target_type & SCAN_XMAS) {
        tcp->th_flags |= (TH_FIN | TH_URG | TH_PUSH);
    }
}

void set_psudo_header(struct pseudo_header *psh, const char *src_ip, struct sockaddr_in *target) {
    psh->source_address = inet_addr(src_ip);
    psh->dest_address = target->sin_addr.s_addr;
    psh->placeholder = 0;
    psh->protocol = IPPROTO_TCP;
    psh->tcp_length = htons(sizeof(struct tcphdr) + 4); // Include MSS option length
}