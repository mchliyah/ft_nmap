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

uint16_t compute_tcp_checksum(struct iphdr *ip, struct tcphdr *tcp) {
    uint32_t sum = 0;
    uint16_t tcp_len = ntohs(ip->tot_len) - (ip->ihl * 4);

    // Pseudo-header
    sum += (ip->saddr >> 16) & 0xFFFF;
    sum += ip->saddr & 0xFFFF;
    sum += (ip->daddr >> 16) & 0xFFFF;
    sum += ip->daddr & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(tcp_len);

    // TCP header
    tcp->check = 0; // Zero checksum field
    uint16_t *ptr = (uint16_t *)tcp;
    for (int i = 0; i < tcp_len / 2; i++) {
        sum += ntohs(ptr[i]);
    }

    // Handle odd length
    if (tcp_len % 2) {
        sum += ((uint8_t *)tcp)[tcp_len - 1] << 8;
    }

    // Fold carries
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

// Generate a random source port like nmap does
uint16_t generate_source_port() {
    return 32768 + (rand() % 28232); // Nmap's range
}

void send_syn(int sock, struct sockaddr_in *target, const char *src_ip, uint16_t src_port, uint32_t *sent_seq) {
    char packet[4096] = {0};
    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // Generate random sequence number
    *sent_seq = rand();

    // IP header
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

    // TCP header
    tcp->source = htons(src_port);
    tcp->dest = target->sin_port;
    tcp->seq = htonl(*sent_seq);
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->ack = 0;
    tcp->fin = 0;
    tcp->rst = 0;
    tcp->psh = 0;
    tcp->urg = 0;
    tcp->window = htons(1024); // Like nmap
    tcp->check = 0;
    tcp->urg_ptr = 0;

    tcp->check = compute_tcp_checksum(ip, tcp);

    printf("SYN to %s:%d from %s:%d (seq=%u)\n",
           inet_ntoa(target->sin_addr), ntohs(target->sin_port),
           src_ip, src_port, *sent_seq);

    if (sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
               (struct sockaddr *)target, sizeof(*target)) < 0) {
        perror("sendto");
    }
}

void *scan_thread(void *arg) {
    scan_thread_data *data = (scan_thread_data *)arg;
    const char *src_ip = get_interface_ip(data->config->ip);

    for (int i = data->start_port; i < data->end_port; i++) {
        int port = data->config->port_list[i];
        uint16_t src_port = generate_source_port();
        uint32_t sent_seq;
        
        struct sockaddr_in target = {
            .sin_family = AF_INET,
            .sin_port = htons(port)
        };
        inet_pton(AF_INET, data->config->ip, &target.sin_addr);

        // Create raw socket === to ckeck later if i need to change it 
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0) {
            perror("socket");
            continue;
        }

        int one = 1;
        if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            perror("setsockopt");
            close(sock);
            continue;
        }

        // Setup capture args
        capture_thread_args *listener_args = malloc(sizeof(*listener_args));
        *listener_args = (capture_thread_args){
            .config = data->config,
            .port = port,
            .target = target,
            .state = STATE_WAITING,
            .src_port = src_port,
            .sent_seq = 0
        };

        pthread_t listener;
        pthread_create(&listener, NULL, capture_responses_debug, listener_args);
        

        usleep(50000);
        send_syn(sock, &target, src_ip, src_port, &sent_seq);
        listener_args->sent_seq = sent_seq;

        struct timespec timeout;
        clock_gettime(CLOCK_REALTIME, &timeout);
        timeout.tv_sec += 8;
        pthread_mutex_lock(&data->config->mutex);
        int result = pthread_cond_timedwait(&data->config->cond, &data->config->mutex, &timeout);
        
        if (result == ETIMEDOUT) {
            printf("Port %d: FILTERED (timeout)\n", port);
            listener_args->state = STATE_FILTERED;
        }
        pthread_mutex_unlock(&data->config->mutex);

        pthread_cancel(listener);
        pthread_join(listener, NULL);
        close(sock);
        
        usleep(100000);
    }
    return NULL;
}