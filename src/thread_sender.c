#include "../include/ft_nmap.h"

uint16_t calculate_udp_checksum(uint16_t *buf, int len) {
    uint32_t sum = 0;
    
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    
    if (len == 1) {
        sum += *(uint8_t *)buf;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return (uint16_t)(~sum);
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
        set_ip_header(ip, g_config.src_ip, &target, IPPROTO_TCP);
        set_tcp_header(tcp, SCAN_SYN);
        tcp->th_dport = htons(current->port);
        ip->ip_sum = csum((unsigned short *)ip, sizeof(struct ip) / 2);
        tcp->th_sum = calculate_tcp_checksum(ip, tcp, tcp_options, 4);
        send_to(data->sock, datagram, sizeof(struct ip) + sizeof(struct tcphdr) + 4, 0,
                   (struct sockaddr *)&target, sizeof(target));

}

void send_null(scan_thread_data *data, t_port *current, struct tcphdr *tcp, struct ip *ip, struct sockaddr_in target, char *datagram, uint8_t *tcp_options) {
    set_ip_header(ip, g_config.src_ip, &target, IPPROTO_TCP);
    set_tcp_header(tcp, SCAN_NULL);
    tcp->th_dport = htons(current->port);
    ip->ip_sum = csum((unsigned short *)ip, sizeof(struct ip) / 2);
    tcp->th_sum = calculate_tcp_checksum(ip, tcp, tcp_options, 4);
    send_to(data->sock, datagram, sizeof(struct ip) + sizeof(struct tcphdr) + 4, 0,
             (struct sockaddr *)&target, sizeof(target));
}


void send_fin(scan_thread_data *data, t_port *current, struct tcphdr *tcp, struct ip *ip, struct sockaddr_in target, char *datagram, uint8_t *tcp_options) {
    set_ip_header(ip, g_config.src_ip, &target, IPPROTO_TCP);
    set_tcp_header(tcp, SCAN_FIN);
    tcp->th_dport = htons(current->port);
    ip->ip_sum = csum((unsigned short *)ip, sizeof(struct ip) / 2);
    tcp->th_sum = calculate_tcp_checksum(ip, tcp, tcp_options, 4);
    send_to(data->sock, datagram, sizeof(struct ip) + sizeof(struct tcphdr) + 4, 0,
             (struct sockaddr *)&target, sizeof(target));
}

void send_xmas(scan_thread_data *data, t_port *current, struct tcphdr *tcp, struct ip *ip, struct sockaddr_in target, char *datagram, uint8_t *tcp_options) {
    set_ip_header(ip, g_config.src_ip, &target, IPPROTO_TCP);
    set_tcp_header(tcp, SCAN_XMAS);
    tcp->th_dport = htons(current->port);
    ip->ip_sum = csum((unsigned short *)ip, sizeof(struct ip) / 2);
    tcp->th_sum = calculate_tcp_checksum(ip, tcp, tcp_options, 4);
    send_to(data->sock, datagram, sizeof(struct ip) + sizeof(struct tcphdr) + 4, 0,
             (struct sockaddr *)&target, sizeof(target));
}

void send_ack(scan_thread_data *data, t_port *current, struct tcphdr *tcp, struct ip *ip, struct sockaddr_in target, char *datagram, uint8_t *tcp_options) {
    set_ip_header(ip, g_config.src_ip, &target, IPPROTO_TCP);
    set_tcp_header(tcp, SCAN_ACK);
    tcp->th_dport = htons(current->port);
    ip->ip_sum = csum((unsigned short *)ip, sizeof(struct ip) / 2);
    tcp->th_sum = calculate_tcp_checksum(ip, tcp, tcp_options, 4);
    send_to(data->sock, datagram, sizeof(struct ip) + sizeof(struct tcphdr) + 4, 0,
             (struct sockaddr *)&target, sizeof(target));
}

uint16_t calculate_checksum(uint16_t *buf, int len) {
    uint32_t sum = 0;
    
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    
    if (len == 1) {
        sum += *(uint8_t *)buf;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return (uint16_t)(~sum);
}

// Common UDP payloads
const uint8_t dns_query[] = {
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 'w', 'w', 'w',
    0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm',
    0x00, 0x00, 0x01, 0x00, 0x01
};

const uint8_t snmp_query[] = {
    0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70,
    0x75, 0x62, 0x6c, 0x69, 0x63, 0xA0, 0x19, 0x02,
    0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
    0x30, 0x0E, 0x30, 0x0C, 0x06, 0x08, 0x2B, 0x06,
    0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00
};

const uint8_t ntp_query[] = {
    0xE3, 0x00, 0x04, 0xFA, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

const uint8_t netbios_query[] = {
    0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4B, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
    0x00, 0x01
};

const uint8_t sip_options[] = {
    'O', 'P', 'T', 'I', 'O', 'N', 'S', ' ',
    's', 'i', 'p', ':', 'e', 'x', 'a', 'm',
    'p', 'l', 'e', '@', 'e', 'x', 'a', 'm',
    'p', 'l', 'e', '.', 'c', 'o', 'm', ' ',
    'S', 'I', 'P', '/', '2', '.', '0', '\r',
    '\n', 'V', 'i', 'a', ':', ' ', 'S', 'I',
    'P', '/', '2', '.', '0', '/', 'U', 'D',
    'P', ' ', 'e', 'x', 'a', 'm', 'p', 'l',
    'e', '.', 'c', 'o', 'm', ';', 'b', 'r',
    'a', 'n', 'c', 'h', '=', 'z', '9', 'h',
    'G', '4', 'b', 'K', '\r', '\n', 'M', 'a',
    'x', '-', 'F', 'o', 'r', 'w', 'a', 'r',
    'd', 's', ':', ' ', '7', '0', '\r', '\n',
    'F', 'r', 'o', 'm', ':', ' ', '<', 's',
    'i', 'p', ':', 'e', 'x', 'a', 'm', 'p',
    'l', 'e', '@', 'e', 'x', 'a', 'm', 'p',
    'l', 'e', '.', 'c', 'o', 'm', '>', ';',
    't', 'a', 'g', '=', '1', '2', '3', '4',
    '5', '\r', '\n', 'T', 'o', ':', ' ', '<',
    's', 'i', 'p', ':', 'e', 'x', 'a', 'm',
    'p', 'l', 'e', '@', 'e', 'x', 'a', 'm',
    'p', 'l', 'e', '.', 'c', 'o', 'm', '>',
    '\r', '\n', 'C', 'a', 'l', 'l', '-', 'I',
    'D', ':', ' ', 'a', 'b', 'c', 'd', 'e',
    'f', 'g', '\r', '\n', 'C', 'S', 'e', 'q',
    ':', ' ', '1', ' ', 'O', 'P', 'T', 'I',
    'O', 'N', 'S', '\r', '\n', 'C', 'o', 'n',
    't', 'a', 'c', 't', ':', ' ', '<', 's',
    'i', 'p', ':', 'e', 'x', 'a', 'm', 'p',
    'l', 'e', '@', 'e', 'x', 'a', 'm', 'p',
    'l', 'e', '.', 'c', 'o', 'm', '>', '\r',
    '\n', 'A', 'c', 'c', 'e', 'p', 't', ':',
    ' ', 'a', 'p', 'p', 'l', 'i', 'c', 'a',
    't', 'i', 'o', 'n', '/', 's', 'd', 'p',
    '\r', '\n', 'C', 'o', 'n', 't', 'e', 'n',
    't', '-', 'L', 'e', 'n', 'g', 't', 'h',
    ':', ' ', '0', '\r', '\n', '\r', '\n'
};

// TFTP read request for filename "default"
const uint8_t tftp_read_request[] = {
    0x00, 0x01, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6C,
    0x74, 0x00, 0x6F, 0x63, 0x74, 0x65, 0x74, 0x00
};

// RPC portmap request
const uint8_t rpc_portmap_request[] = {
    0x80, 0x00, 0x00, 0x28, 0x6F, 0xFD, 0x73, 0x5F,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x01, 0x86, 0xA0, 0x00, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


static const udp_payload_t udp_payloads[] = {
    {53,   "domain",   dns_query,          sizeof(dns_query)},
    {69,   "tftp",     tftp_read_request,  sizeof(tftp_read_request)},
    {111,  "rpcbind",  rpc_portmap_request,sizeof(rpc_portmap_request)},
    {161,  "snmp",     snmp_query,         sizeof(snmp_query)},
    {123,  "ntp",      ntp_query,          sizeof(ntp_query)},
    {137,  "netbios",  netbios_query,      sizeof(netbios_query)},
    {5060, "sip",      sip_options,        sizeof(sip_options)},
    {0,    NULL,       NULL,               0}
};

const udp_payload_t *get_udp_payload(uint16_t port) {
    for (int i = 0; udp_payloads[i].port != 0; i++) {
        if (udp_payloads[i].port == port) {
            return &udp_payloads[i];
        }
    }
    return NULL;
}

int send_udp_probe(int raw_socket, const char *target_ip, uint16_t port) {
    const udp_payload_t *payload_info = get_udp_payload(port);
    const uint8_t *payload_data;
    size_t payload_len;
    
    if (payload_info) {
        payload_data = payload_info->payload;
        payload_len = payload_info->payload_len;
        V_PRINT(2, "Using %s payload for port %d\n", payload_info->service, port);
    } else {
        static const uint8_t empty_payload[] = {0};
        payload_data = empty_payload;
        payload_len = sizeof(empty_payload);
        V_PRINT(2, "Using empty payload for port %d\n", port);
    }

    char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + 512];
    struct iphdr *ip_header = (struct iphdr *)packet;
    struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct iphdr));
    uint8_t *payload = (uint8_t *)(packet + sizeof(struct iphdr) + sizeof(struct udphdr));

    memset(packet, 0, sizeof(packet));
    memcpy(payload, payload_data, payload_len);

    ip_header->version = 4;
    ip_header->ihl = 5;
    ip_header->tos = 0;
    ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len);
    ip_header->id = htons(rand() % 65535);
    ip_header->frag_off = htons(IP_DF);
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_UDP;
    ip_header->saddr = inet_addr(g_config.src_ip);
    ip_header->daddr = inet_addr(target_ip);
    ip_header->check = 0;
    ip_header->check = calculate_checksum((uint16_t *)ip_header, sizeof(struct iphdr));

    udp_header->source = htons(rand() % 30000 + 32768);
    udp_header->dest = htons(port);
    udp_header->len = htons(sizeof(struct udphdr) + payload_len);
    udp_header->check = 0;

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(target_ip);
    dest_addr.sin_port = htons(port);

    if (sendto(raw_socket, packet, sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len, 0,
               (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto");
        return -1;
    }

    return 0;
}

int create_raw_socket(void) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        close(sock);
        return -1;
    }

    return sock;
}

void send_udp(scan_thread_data *data, t_port *current, struct ip *ip, struct sockaddr_in target, char *datagram) {
    (void)datagram; 
    (void)target;
    (void)data;
    (void)ip;
    
    int udp_socket = create_raw_socket();
    if (udp_socket < 0) {
        return;
    }
    
    current->tcp_udp = "udp";
    if (send_udp_probe(udp_socket, g_config.ip, current->port) < 0) {
        fprintf(stderr, "Failed to send probe to port %d\n", current->port);
    }

    close(udp_socket);
}

void send_packets(scan_thread_data *data, t_port *current_port, char *datagram, 
                  struct tcphdr *tcp, struct ip *ip, uint8_t *tcp_options) {
    int start = data->start_range;
    
    while (current_port && start < data->end_range) {
        struct sockaddr_in target = {
            .sin_family = AF_INET,
            .sin_port = htons(current_port->port),
            .sin_addr = { .s_addr = inet_addr(g_config.ip) }
        };
        
        if (g_config.scan_types.syn) send_syn(data, current_port, tcp, ip, target, datagram, tcp_options);
        if (g_config.scan_types.null) send_null(data, current_port, tcp, ip, target, datagram, tcp_options);
        if (g_config.scan_types.fin) send_fin(data, current_port, tcp, ip, target, datagram, tcp_options);
        if (g_config.scan_types.xmas) send_xmas(data, current_port, tcp, ip, target, datagram, tcp_options);
        if (g_config.scan_types.ack) send_ack(data, current_port, tcp, ip, target, datagram, tcp_options);
        if (g_config.scan_types.udp) send_udp(data, current_port, ip, target, datagram);
        
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
    uint8_t *tcp_options = set_options(datagram);

    V_PRINT(2, "Using source IP %s\n", g_config.src_ip);
    send_packets(data, current_port, datagram, tcp, ip, tcp_options);
    
    V_PRINT(1, "Completed scanning %d ports\n", data->end_range - data->start_range);
    return NULL;
}