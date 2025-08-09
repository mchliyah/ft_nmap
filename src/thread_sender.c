#include "../include/ft_nmap.h"


const char* get_interface_ip(const char *target_ip) {
    (void) target_ip;
    //TODO: implement this function to return the source ip address 
    return "10.0.0.78";
}

void init_scan() {
    srand(time(NULL)); // Better random seed
}


//the TCP checksum (RFC 793) like syber pool
uint16_t compute_tcp_checksum(struct iphdr *ip, struct tcphdr *tcp) {
    uint32_t sum = 0;
    uint16_t tcp_len = ntohs(ip->tot_len) - (ip->ihl * 4);

    // Pseudo-header (src IP, dst IP, protocol, TCP length)
    sum += (ip->saddr >> 16) & 0xFFFF;
    sum += ip->saddr & 0xFFFF;
    sum += (ip->daddr >> 16) & 0xFFFF;
    sum += ip->daddr & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(tcp_len);

    // TCP header + payload
    // SYN has no payload but still we may need this for the other types 
    uint16_t *ptr = (uint16_t *)tcp;
    for (int i = 0; i < tcp_len / 2; i++) {
        sum += ptr[i];
        if (sum > 0xFFFF)
            sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // If odd length, pad with zero
    if (tcp_len % 2) {
        uint16_t pad = ((uint8_t *)tcp)[tcp_len - 1] << 8;
        sum += pad;
    }

    // Final one's complement
    sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

// Build a TCP SYN packet (raw socket "Low-level access")
void send_syn(int sock, struct sockaddr_in *target, const char *src_ip) {
    char packet[4096] = {0};
    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // IP header
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->id = htons(getpid() & 0xFFFF);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr(src_ip);
    ip->daddr = target->sin_addr.s_addr;
    ip->check = 0;

    // TCP header
    tcp->source = htons(32768 + (getpid() % 32768));  // Similar to Nmap
    tcp->dest = target->sin_port;
    tcp->seq = htonl(rand() % 4294967295);
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->window = htons(5840);
    tcp->check = 0;
    tcp->urg_ptr = 0;

    // tcp->check = compute_tcp_checksum(ip, tcp);

    printf("SYN to %s:%d from %s:%d\n",
           inet_ntoa(target->sin_addr), ntohs(target->sin_port),
           src_ip, ntohs(tcp->source));

    if (sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
               (struct sockaddr *)target, sizeof(*target)) < 0) {
        perror("sendto");
    }
}


void *scan_thread(void *arg) {
    scan_thread_data *data = (scan_thread_data *)arg;
    const char *src_ip = get_interface_ip(data->config->ip); // Implement this

    for (int i = data->start_port; i < data->end_port; i++) {
        int port = data->config->port_list[i];
        struct sockaddr_in target = {
            .sin_family = AF_INET,
            .sin_port = htons(port)
        };
        inet_pton(AF_INET, data->config->ip, &target.sin_addr);

        // Create raw socket
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0) {
            perror("socket");
            continue;
        }

        // Set IP_HDRINCL
        int one = 1;
        if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            perror("setsockopt");
            close(sock);
            continue;
        }

        // Setup capture args
        capture_thread_args *listner_args = malloc(sizeof(*listner_args));
        *listner_args = (capture_thread_args){
            .config = data->config,
            .port = port,
            .target = target,
            .state = STATE_WAITING
        };

        // Start capture BEFORE sending
        pthread_t listener;
        pthread_create(&listener, NULL, capture_responses, listner_args);
        usleep(100000); // Small delay to ensure capture is ready

        // Send SYN
        send_syn(sock, &target, src_ip);

        // Wait for response
        pthread_join(listener, NULL);
        close(sock);
    }
    return NULL;
}

// // Thread worker function
// void *scan_thread(void *arg) {
//     scan_thread_data *data = (scan_thread_data *)arg;
//     t_config *config = data->config;
    

//     printf("unsigned int max = %u\n", UINT_MAX);
//     printf("Thread %d: Scanning ports %d-%d\n", 
//           data->thread_id, data->start_port, data->end_port - 1);

//     for (int port_idx = data->start_port; port_idx < data->end_port; port_idx++) {
//         int port = config->port_list[port_idx];
//         // struct servent *service = getservbyport(htons(port), "tcp"); 
        
//         printf("config->scan_type_count = %d\n", config->scan_type_count);

//         for (int scan_idx = 0; scan_idx < config->scan_type_count; scan_idx++) {
//             const char *scan_type = config->scan_types[scan_idx];

//             // printf("[Thread %d] Port %d (%s): %s scan - ",
//             //       data->thread_id, port,
//             //       service ? service->s_name : "unknown",
//             //       scan_type);

//             // Common scan preparation
//             struct sockaddr_in target = {
//                 .sin_family = AF_INET,
//                 .sin_port = htons(port)
//             };
//             inet_pton(AF_INET, config->ip, &target.sin_addr);

//             //different scan types
//             // S -> SYN
//             if (strcmp(scan_type, "S") == 0) {
//                 // SYN Scan implementation
//                 int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

//                 if (sock < 0) {
//                     if (errno == EPERM) {
//                         fprintf(stderr, "Error: SYN scan requires root (use sudo )\n");
//                     } else {
//                         perror("socket(SYN)");
//                     }
//                     continue;
//                 }

//                 // int setsockopt(int socket, int level, int option_name,
//                     // const void *option_value, socklen_t option_len);
//                 int one = 1;
//                 if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))) {
//                     perror("setsockopt(IP_HDRINCL)");
//                     close(sock);
//                     continue;
//                 }
//                 // Send SYN packet
//                 send_syn(sock, &target);


//                 capture_thread_args *listner_args = malloc(sizeof(capture_thread_args));
//                 if (!listner_args) {
//                     perror("malloc");
//                     close(sock);
//                     continue;
//                 }

//                 listner_args->config = config;
//                 listner_args->port = port;
//                 listner_args->target = target;

//                 // Set up timeout (e.g., 2 seconds)
//                 int timeout_ms = 50000;

//                 printf("Creating listener thread for port %d...\n", port);
//                 pthread_t listener;
//                 if (pthread_create(&listener, NULL, capture_responses, listner_args) != 0) {
//                     perror("pthread_create");
//                     free(listner_args);
//                     close(sock);
//                     continue;
//                 }
//                 pthread_mutex_lock(&config->mutex);
//                 struct timespec ts;
//                 clock_gettime(CLOCK_REALTIME, &ts);
//                 ts.tv_sec += timeout_ms / 1000;
//                 ts.tv_nsec += (timeout_ms % 1000) * 1000000;
//                 if (ts.tv_nsec >= 1000000000) {
//                     ts.tv_sec++;
//                     ts.tv_nsec -= 1000000000;
//                 }

//                 int ret = pthread_cond_timedwait(&config->cond, &config->mutex, &ts);
//                 pthread_mutex_unlock(&config->mutex);

//                 if (ret == ETIMEDOUT) {
//                     printf("Timeout reached, port %d: filtered (no response)\n", port);
//                     pthread_cancel(listener);
//                 }
//                 pthread_join(listener, NULL);
//                 close(sock);
            
//             }
//             // TODO: other scan types (NULL, FIN, XMAS, ACK)
//             // N -> NULL
//             else if (strcmp(scan_type, "N") == 0){
//                 continue;
//             }
//             // A -> ACK
//             else if (strcmp(scan_type, "A") == 0){
//                 continue;
//             }
//             // F -> FIN
//             else if (strcmp(scan_type, "F") == 0){
//                 continue;
//             }
//             // X -> XMAS
//             else if (strcmp(scan_type, "X") == 0){
//                 continue;
//             }
//             // U -> UDP
//             else if (strcmp(scan_type, "U") == 0) {
//                 // UDP Scan implementation
//                 int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
//                 if (sock < 0) {
//                     perror("socket(UDP)");
//                     continue;
//                 }
                
//                 // UDP scan logic
//                 if (connect(sock, (struct sockaddr *)&target, sizeof(target)) == 0) {
//                     printf("UDP open\n");
//                 } else {
//                     printf("UDP %s\n", errno == ECONNREFUSED ? "closed" : "filtered");
//                 }
//                 close(sock);
//             }
//             else {
//                 // printf("Scan type not implemented\n");
//                 continue;
//             }
//         }
//     }
//     return NULL;
// }



