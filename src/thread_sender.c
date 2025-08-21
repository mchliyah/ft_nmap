#include "../include/ft_nmap.h"

void send_syn(int sock, struct sockaddr_in *target, char *datagram) {

    pthread_mutex_lock(&g_config.mutex);
    if (sendto(sock, datagram, sizeof(struct ip) + sizeof(struct tcphdr), 0,
               (struct sockaddr *)target, sizeof(*target)) < 0) {
        perror("sendto");
        }
    // } else {
    //     printf("Packet sent successfully\n");
    // }
    pthread_mutex_unlock(&g_config.mutex);
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



void *scan_thread(void *arg) {
    scan_thread_data *data = (scan_thread_data *)arg;
    
    // Allocate space for IP header + TCP header + MSS option
    char datagram[4096] = {0};
    struct ip *ip = (struct ip *)datagram;
    struct tcphdr *tcp = (struct tcphdr *)(datagram + sizeof(struct ip));
    
    // Add MSS option (4 bytes)
    uint8_t *tcp_options = (uint8_t *)(datagram + sizeof(struct ip) + sizeof(struct tcphdr));
    tcp_options[0] = 0x02; // MSS option kind
    tcp_options[1] = 0x04; // MSS option length
    tcp_options[2] = 0x05; // MSS value high byte (1460 = 0x05B4)
    tcp_options[3] = 0xB4; // MSS value low byte
    
    const char *src_ip = get_interface_ip(g_config.ip);
    
    pthread_mutex_lock(&g_config.mutex);
    t_port *current = g_config.port_list;
    while (current && current->port < data->start_range) {
        current = current->next;
    }
    pthread_mutex_unlock(&g_config.mutex);
    
    if (!current) {
        printf("Thread %d: No ports to scan\n", data->thread_id);
        return NULL;
    }

    printf("Thread %d: Starting with port %d\n", data->thread_id, current->port);

    while (current && !g_config.scan_complete) {
        // Set up target for this port
        struct sockaddr_in target = {
            .sin_family = AF_INET,
            .sin_port = htons(current->port),
            .sin_addr = { .s_addr = inet_addr(g_config.ip) }
        };

        // Initialize headers
        set_ip_header(ip, src_ip, &target);
        set_tcp_header(tcp, SCAN_SYN);
        tcp->th_dport = htons(current->port);
        
        // Calculate IP checksum
        ip->ip_sum = 0;
        ip->ip_sum = csum((u_short *)ip, sizeof(struct ip) / 2);
        
        // Calculate TCP checksum including options
        tcp->th_sum = 0;
        tcp->th_sum = calculate_tcp_checksum(ip, tcp, tcp_options, 4);
        
        // Debug output
        // char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
        // inet_ntop(AF_INET, &ip->ip_src, src_ip_str, INET_ADDRSTRLEN);
        // inet_ntop(AF_INET, &ip->ip_dst, dst_ip_str, INET_ADDRSTRLEN);
        
        // printf("Sending to %s:%d - IP len: %d, TTL: %d, TCP flags: 0x%02x\n", 
        //        dst_ip_str, current->port, ntohs(ip->ip_len), ip->ip_ttl, tcp->th_flags);
        
        // Send packet (IP header + TCP header + options)
        if (sendto(data->sock, datagram, sizeof(struct ip) + sizeof(struct tcphdr) + 4, 0,
                   (struct sockaddr *)&target, sizeof(target)) < 0) {
            perror("sendto");
                   }
        // } else {
        //     printf("Packet sent successfully to %s:%d\n", dst_ip_str, current->port);
        // }
        
        // Small delay
        usleep(1000);
        
        // Move to next port
        pthread_mutex_lock(&g_config.mutex);
        current = current->next;
        
        // Check if we've reached the end of this thread's range
        if (current && current->port > data->end_range) {
            current = NULL;
        }
        pthread_mutex_unlock(&g_config.mutex);
    }

    printf("Thread %d: finished sending packets\n", data->thread_id);
    return NULL;
}