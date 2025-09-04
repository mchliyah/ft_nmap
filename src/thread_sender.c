#include "../include/ft_nmap.h"

void    send_to(int sock, char *datagram, size_t len, int flags, struct sockaddr *dest_addr, socklen_t addrlen) {
    if (sendto(sock, datagram, len, flags, dest_addr, addrlen) < 0) {
        perror("sendto");
        exit(EXIT_FAILURE);
    }
}

void send_syn(scan_thread_data *data ,t_port *current, struct tcphdr *tcp, struct ip *ip, struct sockaddr_in target, char *datagram, uint8_t *tcp_options) {

        set_tcp_header(tcp, SCAN_SYN);
        tcp->th_dport = htons(current->port);
        
        ip->ip_sum = 0;
        ip->ip_sum = csum((unsigned short *)ip, sizeof(struct ip) / 2);
        
        tcp->th_sum = 0;
        tcp->th_sum = calculate_tcp_checksum(ip, tcp, tcp_options, 4);

        current->tcp_udp = "tcp";
        send_to(data->sock, datagram, sizeof(struct ip) + sizeof(struct tcphdr) + 4, 0,
                   (struct sockaddr *)&target, sizeof(target));

}

void send_null(scan_thread_data *data, t_port *current, struct tcphdr *tcp, struct ip *ip, struct sockaddr_in target, char *datagram, uint8_t *tcp_options) {
    
    set_tcp_header(tcp, SCAN_NULL);
    tcp->th_dport = htons(current->port);
    ip->ip_sum = 0;
    ip->ip_sum = csum((unsigned short *)ip, sizeof(struct ip) / 2);
    tcp->th_sum = 0;
    tcp->th_sum = calculate_tcp_checksum(ip, tcp, tcp_options, 4);
    current->tcp_udp = "tcp";
    send_to(data->sock, datagram, sizeof(struct ip) + sizeof(struct tcphdr) + 4, 0,
             (struct sockaddr *)&target, sizeof(target));
}


void send_fin(scan_thread_data *data, t_port *current, struct tcphdr *tcp, struct ip *ip, struct sockaddr_in target, char *datagram, uint8_t *tcp_options) {

    set_tcp_header(tcp, SCAN_FIN);
    tcp->th_dport = htons(current->port);

    ip->ip_sum = 0;
    ip->ip_sum = csum((unsigned short *)ip, sizeof(struct ip) / 2);

    tcp->th_sum = 0;
    tcp->th_sum = calculate_tcp_checksum(ip, tcp, tcp_options, 4);
    current->tcp_udp = "tcp";
    send_to(data->sock, datagram, sizeof(struct ip) + sizeof(struct tcphdr) + 4, 0,
             (struct sockaddr *)&target, sizeof(target));
}

void send_xmas(scan_thread_data *data, t_port *current, struct tcphdr *tcp, struct ip *ip, struct sockaddr_in target, char *datagram, uint8_t *tcp_options) {

    set_tcp_header(tcp, SCAN_XMAS);
    tcp->th_dport = htons(current->port);

    ip->ip_sum = 0;
    ip->ip_sum = csum((unsigned short *)ip, sizeof(struct ip) / 2);

    tcp->th_sum = 0;
    tcp->th_sum = calculate_tcp_checksum(ip, tcp, tcp_options, 4);
    current->tcp_udp = "tcp";
    send_to(data->sock, datagram, sizeof(struct ip) + sizeof(struct tcphdr) + 4, 0,
             (struct sockaddr *)&target, sizeof(target));
}

void send_ack(scan_thread_data *data, t_port *current, struct tcphdr *tcp, struct ip *ip, struct sockaddr_in target, char *datagram, uint8_t *tcp_options) {

    set_tcp_header(tcp, SCAN_ACK);
    tcp->th_dport = htons(current->port);

    ip->ip_sum = 0;
    ip->ip_sum = csum((unsigned short *)ip, sizeof(struct ip) / 2);

    tcp->th_sum = 0;
    tcp->th_sum = calculate_tcp_checksum(ip, tcp, tcp_options, 4);
    current->tcp_udp = "tcp";
    send_to(data->sock, datagram, sizeof(struct ip) + sizeof(struct tcphdr) + 4, 0,
             (struct sockaddr *)&target, sizeof(target));
}

void send_udp(scan_thread_data *data, t_port *current, struct ip *ip, struct sockaddr_in target, char *datagram) {

    struct udphdr *udp = (struct udphdr *)(datagram + sizeof(struct ip));
    
    udp->uh_sport = htons(generate_source_port());
    udp->uh_dport = htons(current->port);
    udp->uh_ulen = htons(sizeof(struct udphdr));
    udp->uh_sum = 0;
    
    set_ip_header(ip, g_config.src_ip, &target);
    ip->ip_p = IPPROTO_UDP;
    ip->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr));

    ip->ip_sum = 0;
    ip->ip_sum = csum((unsigned short *)ip, sizeof(struct ip) / 2);
    current->tcp_udp = "udp";
    if (sendto(data->sock, datagram, sizeof(struct ip) + sizeof(struct udphdr), 0,
               (struct sockaddr *)&target, sizeof(target)) < 0) {
        perror("sendto UDP");
        fprintf(stderr, "Failed to send UDP packet to %s:%d\n", 
                inet_ntoa(target.sin_addr), current->port);
    }
}

void send_packets(scan_thread_data *data, t_port *current_port, char *datagram, struct tcphdr *tcp, struct ip *ip, uint8_t *tcp_options, const char *src_ip) {

    int start = data->start_range;
    while (current_port && start < data->end_range) {
        V_PRINT(3, "Thread %d: Sending probes to %s:%d\n", 
                data->thread_id, inet_ntoa(data->target.sin_addr), current_port->port);
        struct sockaddr_in target = {
            .sin_family = AF_INET,
            .sin_port = htons(current_port->port),
            .sin_addr = { .s_addr = inet_addr(g_config.ip) }
        };
        int packet_count = 0;
        set_ip_header(ip, src_ip, &target);
        for (int scan = 0; scan < g_config.scan_type_count; scan++) {
            if (g_config.scan_types.syn & SCAN_SYN){
                V_PRINT(3, "Thread %d: Sending SYN probe to port %d\n", 
                        data->thread_id, current_port->port);
                send_syn(data, current_port, tcp, ip, target, datagram, tcp_options);
            }
            else if (g_config.scan_types.null & SCAN_NULL){
                V_PRINT(3, "Thread %d: Sending NULL probe to port %d\n", 
                        data->thread_id, current_port->port);
                send_null(data, current_port, tcp, ip, target, datagram, tcp_options);
            }
            else if (g_config.scan_types.fin & SCAN_FIN){
                V_PRINT(3, "Thread %d: Sending FIN probe to port %d\n", 
                        data->thread_id, current_port->port);
                send_fin(data, current_port, tcp, ip, target, datagram, tcp_options);
            }
            else if (g_config.scan_types.xmas & SCAN_XMAS){
                V_PRINT(3, "Thread %d: Sending XMAS probe to port %d\n", 
                        data->thread_id, current_port->port);
                send_xmas(data, current_port, tcp, ip, target, datagram, tcp_options);
            }
            else if (g_config.scan_types.ack & SCAN_ACK){
                V_PRINT(3, "Thread %d: Sending ACK probe to port %d\n", 
                        data->thread_id, current_port->port);
                send_ack(data, current_port, tcp, ip, target, datagram, tcp_options);
            }
            else if (g_config.scan_types.udp & SCAN_UDP){
                V_PRINT(3, "Thread %d: Sending UDP probe to port %d\n", 
                        data->thread_id, current_port->port);
                send_udp(data, current_port, ip, target, datagram);
            }
        }
        pthread_mutex_lock(&g_config.port_mutex);
        current_port = current_port->next;
        start++;
        pthread_mutex_unlock(&g_config.port_mutex);
        V_PRINT(2, "Thread %d: Sent %d packets\n", data->thread_id, packet_count);
    }


}

uint8_t *set_options(char *datagram) {
    uint8_t *tcp_options = (uint8_t *)(datagram + sizeof(struct ip) + sizeof(struct tcphdr));
    tcp_options[0] = 0x02;
    tcp_options[1] = 0x04;
    tcp_options[2] = 0x05;
    tcp_options[3] = 0xB4;
    return tcp_options;
}

void *scan_thread(void *arg) {

    scan_thread_data *data = (scan_thread_data *)arg;
    V_PRINT(1, "Thread %d: Starting scan of ports %d to %d\n", 
        data->thread_id, data->start_range, data->end_range);
    pthread_mutex_lock(&g_config.port_mutex);
    t_port *current_port = data->current;
    if (!current_port) {
        printf("Thread %d: No ports to scan\n", data->thread_id);
        return NULL;
    }
    pthread_mutex_unlock(&g_config.port_mutex);
    int start_range = data->start_range;
    int end_range = data->end_range;

    t_port *end_port = current_port;
    while (end_port && start_range <= end_range) {
        end_port = end_port->next;
        start_range++;
    }

    char datagram[4096] = {0};
    struct tcphdr *tcp = (struct tcphdr *)(datagram + sizeof(struct ip));
    struct ip *ip = (struct ip *)datagram;
    const char *src_ip = get_interface_ip(g_config.ip);
    uint8_t *tcp_options = set_options(datagram);


    V_PRINT(2, "Thread %d: Using source IP %s\n", data->thread_id, src_ip);

    send_packets(data, current_port, datagram, tcp, ip, tcp_options, src_ip);
    
    V_PRINT(1, "Thread %d: Completed scanning %d ports\n", 
            data->thread_id, data->end_range - data->start_range + 1);
    return NULL;
}