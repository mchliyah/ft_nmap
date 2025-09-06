#include "../include/ft_nmap.h"

// Helper function to calculate UDP checksum
uint16_t calculate_udp_checksum(struct ip *ip, struct udphdr *udp, char *payload, size_t payload_size) {
    // Pseudo header for UDP checksum calculation
    struct pseudo_header {
        uint32_t src_addr;
        uint32_t dest_addr;
        uint8_t placeholder;
        uint8_t protocol;
        uint16_t udp_length;
    } pseudo_hdr;
    
    pseudo_hdr.src_addr = ip->ip_src.s_addr;
    pseudo_hdr.dest_addr = ip->ip_dst.s_addr;
    pseudo_hdr.placeholder = 0;
    pseudo_hdr.protocol = IPPROTO_UDP;
    pseudo_hdr.udp_length = udp->uh_ulen;
    
    // Create checksum buffer
    char checksum_buffer[sizeof(struct pseudo_header) + sizeof(struct udphdr) + payload_size];
    memcpy(checksum_buffer, &pseudo_hdr, sizeof(struct pseudo_header));
    memcpy(checksum_buffer + sizeof(struct pseudo_header), udp, sizeof(struct udphdr));
    if (payload_size > 0) {
        memcpy(checksum_buffer + sizeof(struct pseudo_header) + sizeof(struct udphdr), payload, payload_size);
    }
    
    return csum((unsigned short *)checksum_buffer, (sizeof(struct pseudo_header) + sizeof(struct udphdr) + payload_size) / 2);
}


void    send_to(int sock, char *datagram, size_t len, int flags, struct sockaddr *dest_addr, socklen_t addrlen) {

    pthread_mutex_lock(&g_config.socket_mutex);
    if (sendto(sock, datagram, len, flags, dest_addr, addrlen) < 0) {
        perror("sendto");
        exit(EXIT_FAILURE);
    }
    g_config.packets_sent++;
    pthread_mutex_unlock(&g_config.socket_mutex);
}

void send_syn(scan_thread_data *data ,t_port *current, struct tcphdr *tcp, struct ip *ip, struct sockaddr_in target, char *datagram, uint8_t *tcp_options) {
        set_ip_header(ip, g_config.src_ip, &target, IPPROTO_TCP);  // Fixed: was IPPROTO_UDP
        set_tcp_header(tcp, SCAN_SYN);
        tcp->th_dport = htons(current->port);
        ip->ip_sum = csum((unsigned short *)ip, sizeof(struct ip) / 2);
        tcp->th_sum = calculate_tcp_checksum(ip, tcp, tcp_options, 4);
        send_to(data->sock, datagram, sizeof(struct ip) + sizeof(struct tcphdr) + 4, 0,
                   (struct sockaddr *)&target, sizeof(target));

}

void send_null(scan_thread_data *data, t_port *current, struct tcphdr *tcp, struct ip *ip, struct sockaddr_in target, char *datagram, uint8_t *tcp_options) {
    set_ip_header(ip, g_config.src_ip, &target, IPPROTO_TCP);  // Fixed: was IPPROTO_UDP
    set_tcp_header(tcp, SCAN_NULL);
    tcp->th_dport = htons(current->port);
    ip->ip_sum = csum((unsigned short *)ip, sizeof(struct ip) / 2);
    tcp->th_sum = calculate_tcp_checksum(ip, tcp, tcp_options, 4);
    send_to(data->sock, datagram, sizeof(struct ip) + sizeof(struct tcphdr) + 4, 0,
             (struct sockaddr *)&target, sizeof(target));
}


void send_fin(scan_thread_data *data, t_port *current, struct tcphdr *tcp, struct ip *ip, struct sockaddr_in target, char *datagram, uint8_t *tcp_options) {
    set_ip_header(ip, g_config.src_ip, &target, IPPROTO_TCP);  // Fixed: was IPPROTO_UDP
    set_tcp_header(tcp, SCAN_FIN);
    tcp->th_dport = htons(current->port);
    ip->ip_sum = csum((unsigned short *)ip, sizeof(struct ip) / 2);
    tcp->th_sum = calculate_tcp_checksum(ip, tcp, tcp_options, 4);
    send_to(data->sock, datagram, sizeof(struct ip) + sizeof(struct tcphdr) + 4, 0,
             (struct sockaddr *)&target, sizeof(target));
}

void send_xmas(scan_thread_data *data, t_port *current, struct tcphdr *tcp, struct ip *ip, struct sockaddr_in target, char *datagram, uint8_t *tcp_options) {
    set_ip_header(ip, g_config.src_ip, &target, IPPROTO_TCP);  // Fixed: was IPPROTO_UDP
    set_tcp_header(tcp, SCAN_XMAS);
    tcp->th_dport = htons(current->port);
    ip->ip_sum = csum((unsigned short *)ip, sizeof(struct ip) / 2);
    tcp->th_sum = calculate_tcp_checksum(ip, tcp, tcp_options, 4);
    send_to(data->sock, datagram, sizeof(struct ip) + sizeof(struct tcphdr) + 4, 0,
             (struct sockaddr *)&target, sizeof(target));
}

void send_ack(scan_thread_data *data, t_port *current, struct tcphdr *tcp, struct ip *ip, struct sockaddr_in target, char *datagram, uint8_t *tcp_options) {
    set_ip_header(ip, g_config.src_ip, &target, IPPROTO_TCP);  // Fixed: was IPPROTO_UDP
    set_tcp_header(tcp, SCAN_ACK);
    tcp->th_dport = htons(current->port);
    ip->ip_sum = csum((unsigned short *)ip, sizeof(struct ip) / 2);
    tcp->th_sum = calculate_tcp_checksum(ip, tcp, tcp_options, 4);
    send_to(data->sock, datagram, sizeof(struct ip) + sizeof(struct tcphdr) + 4, 0,
             (struct sockaddr *)&target, sizeof(target));
}

void add_udp_payload(uint16_t port, char *payload, size_t *payload_size) {
    switch(port) {
        case 53: // DNS query - similar to nmap
            memcpy(payload, "\x00\x1e\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01", 17);
            *payload_size = 17;
            break;
        case 67: // DHCP Discover
        case 68:
            memcpy(payload, "\x01\x01\x06\x00\x00\x00\x3d\x1d\x00\x00\x00\x00\x00\x00\x00\x00", 16);
            *payload_size = 16;
            break;
        case 161: // SNMP GetRequest
            memcpy(payload, "\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00", 40);
            *payload_size = 40;
            break;
        case 123: // NTP request
            memcpy(payload, "\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 48);
            *payload_size = 48;
            break;
        case 137: // NetBIOS Name Service - Fixed hex escape issue
            {
                // Build the payload byte by byte to avoid hex escape issues
                unsigned char netbios_payload[] = {
                    0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x20, 'C', 'K', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
                    0x00, 0x00, 0x21, 0x00, 0x01
                };
                memcpy(payload, netbios_payload, sizeof(netbios_payload));
                *payload_size = sizeof(netbios_payload);
            }
            break;
        case 1434: // MS-SQL Monitor
            memcpy(payload, "\x02", 1);
            *payload_size = 1;
            break;
        default:
            // Empty payload for other ports (like nmap does)
            *payload_size = 0;
    }
}

void send_udp(scan_thread_data *data, t_port *current, struct ip *ip, struct sockaddr_in target, char *datagram) {
    struct udphdr *udp = (struct udphdr *)(datagram + sizeof(struct ip));
    char payload[1024];
    size_t payload_size = 0;
    
    // Clear the datagram for UDP packet
    memset(datagram, 0, 4096);
    
    add_udp_payload(current->port, payload, &payload_size);
    
    // Generate random source port (like nmap)
    udp->uh_sport = htons(generate_source_port());
    udp->uh_dport = htons(current->port);
    udp->uh_ulen = htons(sizeof(struct udphdr) + payload_size);
    udp->uh_sum = 0; // Let kernel calculate or calculate manually
    
    // Set IP header for UDP
    set_ip_header(ip, g_config.src_ip, &target, IPPROTO_UDP);
    ip->ip_p = IPPROTO_UDP;
    ip->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + payload_size);
    ip->ip_sum = 0;
    ip->ip_sum = csum((unsigned short *)ip, sizeof(struct ip) / 2);
    
    // Copy payload if any
    if (payload_size > 0) {
        memcpy(datagram + sizeof(struct ip) + sizeof(struct udphdr), payload, payload_size);
    }
    
    // Calculate UDP checksum (optional, can be 0 for UDP)
    udp->uh_sum = calculate_udp_checksum(ip, udp, payload, payload_size);
    
    PRINT_DEBUG("Sending UDP probe to port %d form source with payload size %zu\n", current->port, payload_size);
    send_to(data->sock, datagram, sizeof(struct ip) + sizeof(struct udphdr) + payload_size, 0,
           (struct sockaddr *)&target, sizeof(target));
}


void send_packets(scan_thread_data *data, t_port *current_port, char *datagram, struct tcphdr *tcp, struct ip *ip, uint8_t *tcp_options) {

    int start = data->start_range;
    PRINT_DEBUG("scan type count = %d \n", g_config.scan_type_count);
    while (current_port && start < data->end_range) {
        struct sockaddr_in target = {
            .sin_family = AF_INET,
            .sin_port = htons(current_port->port),
            .sin_addr = { .s_addr = inet_addr(g_config.ip) }
        };
        
        // Send packets based on scan type
        if (g_config.scan_types.syn & SCAN_SYN) send_syn(data, current_port, tcp, ip, target, datagram, tcp_options);
        if (g_config.scan_types.null & SCAN_NULL) send_null(data, current_port, tcp, ip, target, datagram, tcp_options);
        if (g_config.scan_types.fin & SCAN_FIN) send_fin(data, current_port, tcp, ip, target, datagram, tcp_options);
        if (g_config.scan_types.xmas & SCAN_XMAS) send_xmas(data, current_port, tcp, ip, target, datagram, tcp_options);
        if (g_config.scan_types.ack & SCAN_ACK) send_ack(data, current_port, tcp, ip, target, datagram, tcp_options);
        if (g_config.scan_types.udp & SCAN_UDP) send_udp(data, current_port, ip, target, datagram);
        
        // Small delay to avoid overwhelming the target (like nmap does)
        usleep(1000);
        
        pthread_mutex_lock(&g_config.port_mutex);
        current_port = current_port->next;
        start++;
        pthread_mutex_unlock(&g_config.port_mutex);
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
    V_PRINT(1, "Starting scan of ports %d to %d\n", data->start_range, data->end_range);
    pthread_mutex_lock(&g_config.port_mutex);
    t_port *current_port = data->current;
    if (!current_port) {
        fprintf(stderr, "No ports to scan\n");
        exit(EXIT_FAILURE);
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

    V_PRINT(2, "Using source IP %s\n", src_ip);
    send_packets(data, current_port, datagram, tcp, ip, tcp_options);
    
    V_PRINT(1, "Completed scanning %d ports\n", data->end_range - data->start_range);
    return NULL;
}