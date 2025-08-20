#include "../include/ft_nmap.h"

void send_syn(int sock, struct sockaddr_in *target, char *datagram) {

    pthread_mutex_lock(&g_config.mutex);
    if (sendto(sock, datagram, sizeof(struct ip) + sizeof(struct tcphdr), 0,
               (struct sockaddr *)target, sizeof(*target)) < 0) {
        perror("sendto");
    } else {
        printf("Packet sent successfully\n");
    }
    pthread_mutex_unlock(&g_config.mutex);
    }

void *scan_thread(void *arg) {

    puts("Starting scan thread...");
    scan_thread_data *data = (scan_thread_data *)arg;
    char datagram[4096] = {0};
    struct ip *ip = (struct ip *)datagram;
    struct tcphdr *tcp = (struct tcphdr *)(datagram + sizeof(struct ip));
    struct pseudo_header psh;
    const char *src_ip = get_interface_ip(g_config.ip);
    t_port *current = g_config.port_list;
    // go to the start port
    while (current && current->port < data->start_range) {
        current = current->next;
    }
    int port = current->port;

    struct sockaddr_in target = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = { .s_addr = inet_addr(g_config.ip) }
    };
    // uint16_t src_port = generate_source_port();

    if (!data) {
        fprintf(stderr, "Invalid thread data\n");
        pthread_exit(NULL);
    }
    fprintf(stderr, "Thread %d: Scanning ports from %d to %d\n", data->thread_id, data->start_range, data->end_range);
    set_ip_header(ip, src_ip, &target);
    set_tcp_header(tcp, current ? current->scan_type : SCAN_SYN);
    
    fprintf(stderr, "==================================\n");
    // printing curent conditions befor the loop
    printf("curent port: %d, start_range: %d, end_range: %d, scan_complete: %d\n",
        current ? current->port : -1, data->start_range, data->end_range, g_config.scan_complete);
        fprintf(stderr, "==================================\n");
    while (current && data->start_range <= data->end_range && !g_config.scan_complete) {
        tcp->dest = htons(current->port);
        set_psudo_header(&psh, src_ip, &target);
        memcpy(&psh.tcp, tcp, sizeof(struct tcphdr));
        ip->ip_dst = target.sin_addr;
        ip->ip_sum = csum((u_short *)ip, ip->ip_len >> 1);
        tcp->check = csum((unsigned short *)&psh, sizeof(struct pseudo_header));
        // Check for timeout before each port scan
        fprintf(stderr, "==================================\n");
        if (g_config.scan_start_time > 0 && (time(NULL) - g_config.scan_start_time) > 30) {
            printf("Thread %d: Scan timeout reached during port scanning\n", data->thread_id);
            break;
        }
        // Send SYN packet
        printf("Thread %d: Sending SYN to %s:%d from %s\n", data->thread_id, g_config.ip, port, src_ip);
        
        // Print debug information - fix inet_ntoa static buffer issue
        char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip->ip_src, src_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip->ip_dst, dst_ip_str, INET_ADDRSTRLEN);
        printf("IP Header 79 : src=%s, dst=%s, len=%d\n", src_ip_str, dst_ip_str, ntohs(ip->ip_len));
        // Send packet
        send_syn(data->sock, &target, datagram);
        // Small delay to avoid flooding
        usleep(1000); // 1ms delay between packets


        // Move to the next port in the linked list
        pthread_mutex_lock(&g_config.mutex);
        current = current->next;
        pthread_mutex_unlock(&g_config.mutex);
    }

    printf("Thread %d: finished sending packets\n", data->thread_id);
    return NULL;
}
