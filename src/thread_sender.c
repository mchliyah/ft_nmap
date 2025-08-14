#include "../include/ft_nmap.h"

const char* get_interface_ip(const char *target_ip) {
    struct ifaddrs *ifaddr, *ifa;
    uint32_t target = inet_addr(target_ip);
    static char ip_str[INET_ADDRSTRLEN];
    
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return "10.0.0.78"; // fallback
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;
        
        // Skip loopback
        if (strcmp(ifa->ifa_name, "lo") == 0)
            continue;

        struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
        struct sockaddr_in *mask = (struct sockaddr_in *)ifa->ifa_netmask;

        // Check if target is in same subnet
        if (mask && (addr->sin_addr.s_addr & mask->sin_addr.s_addr) == 
            (target & mask->sin_addr.s_addr)) {
            inet_ntop(AF_INET, &addr->sin_addr, ip_str, INET_ADDRSTRLEN);
            freeifaddrs(ifaddr);
            return ip_str;
        }
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;
        if (strcmp(ifa->ifa_name, "lo") == 0)
            continue;
        
        struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
        inet_ntop(AF_INET, &addr->sin_addr, ip_str, INET_ADDRSTRLEN);
        freeifaddrs(ifaddr);
        return ip_str;
    }

    freeifaddrs(ifaddr);
    return "10.0.0.78"; // ultimate fallback
}

void init_scan() {
    srand(time(NULL));
}

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
void send_syn(int sock, struct sockaddr_in *target, const char *src_ip, 
             uint16_t src_port, int dest_port) {
    char datagram[4096] = {0};
    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcp = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    struct pseudo_header psh;

    set_ip_header(iph, src_ip, target);
    tcp->source = htons(src_port);
    tcp->dest = htons(dest_port);
    tcp->seq = htonl(rand());
    tcp->ack_seq = 0;
    tcp->doff = 5;  // TCP header size (5 * 4 = 20 bytes)
    tcp->syn = 1;
    tcp->window = htons(14600);
    tcp->check = 0;
    tcp->urg_ptr = 0;

    // Add TCP options (MSS)
    uint8_t *options = (uint8_t *)(tcp + 1);
    options[0] = 0x02;  // MSS option kind
    options[1] = 0x04;  // Length
    *(uint16_t *)(options + 2) = htons(1460);  // MSS value
    
    // Update IP length to include options
    iph->tot_len = htons(sizeof(struct iphdr) + 24);

    // Calculate IP checksum
    iph->check = csum((unsigned short *)datagram, iph->tot_len >> 1);

    // Build pseudo-header for TCP checksum
    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(24);  // TCP header + options
    memcpy(&psh.tcp, tcp, sizeof(struct tcphdr));  // Include options

    // Calculate TCP checksum
    tcp->check = csum((unsigned short *)&psh, sizeof(struct pseudo_header));

    // Send packet
    if (sendto(sock, datagram, ntohs(iph->tot_len), 0,
               (struct sockaddr *)target, sizeof(*target)) < 0) {
        perror("sendto");
    }
}
void block_rst(int src_port) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "iptables -A OUTPUT -p tcp --tcp-flags RST RST "
             "--sport %d -j DROP",
             src_port);
    int s = system(cmd);
    if (s == -1)
        return;
}

void unblock_rst(int src_port) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "iptables -D OUTPUT -p tcp --tcp-flags RST RST "
             "--sport %d -j DROP",
             src_port);
    int s = system(cmd);
    if (s == -1)
        return;
}

void process_packet(unsigned char *buffer, int size) {
    (void)size; 
    struct iphdr *iph = (struct iphdr *)buffer;
    if (iph->protocol != IPPROTO_TCP) return;

    unsigned short iphdrlen = iph->ihl * 4;
    struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen);

    // struct sockaddr_in source;
    // source.sin_addr.s_addr = iph->saddr;

    // Check if this is a response to our scan
    if (tcph->syn && tcph->ack) {
        printf("Port %d: OPEN\n", ntohs(tcph->source));
    } else if (tcph->rst) {
        printf("Port %d: CLOSED\n", ntohs(tcph->source));
    }
}



void *start_listner(void *arg) {
    t_config *config = (t_config *)arg;
    int sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw < 0) {
        perror("Sniffer socket failed");
        return NULL;
    }

    unsigned char buffer[65536];
    struct sockaddr saddr;
    socklen_t saddr_size = sizeof(saddr);

    config->scaner_on = 1;
    while (config->scaner_on) {
        int data_size = recvfrom(sock_raw, buffer, sizeof(buffer), 0, &saddr, &saddr_size);
        if (data_size < 0) {
            if (config->scaner_on) perror("recvfrom failed");
            break;
        }
        process_packet(buffer, data_size);
    }
    close(sock_raw);
    return NULL;
}

void *scan_thread(void *arg) {
    scan_thread_data *data = (scan_thread_data *)arg;
    const char *src_ip = get_interface_ip(data->config->ip);

    // Start global sniffer thread
    pthread_t sniffer_thread;
    if (pthread_create(&sniffer_thread, NULL, start_listner, &data->config) != 0) {
        perror("Failed to create sniffer thread");
        return NULL;
    }

    // Give sniffer time to initialize
    usleep(500000);

    for (int i = data->start_port; i < data->end_port; i++) {
        int port = data->config->port_list[i];
        uint16_t src_port = generate_source_port();
        
        struct sockaddr_in target = {
            .sin_family = AF_INET,
            .sin_port = htons(port),
            .sin_addr = { .s_addr = inet_addr(data->config->ip) }
        };

        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0) {
            perror("socket");
            continue;
        }

        int one = 1;
        if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))) {
            perror("setsockopt");
            close(sock);
            continue;
        }

        // Block RST packets for this source port
        // block_rst(src_port);
        
        // Send SYN packet
        send_syn(sock, &target, src_ip, src_port, port);
        
        // Wait for response
        usleep(500);
        
        // Unblock RST
        // unblock_rst(src_port);
        close(sock);
    }

    // Stop sniffer
    data->config->scaner_on = 0;
    pthread_join(sniffer_thread, NULL);
    
    return NULL;
}