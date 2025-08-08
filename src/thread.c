
#include "../include/ft_nmap.h"

// Condition variable and mutex for synchronization
pthread_cond_t cond_var = PTHREAD_COND_INITIALIZER;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
int inner_thread_finished = 0;

// inner_thread to Listen for Responses
void *capture_responses(void *arg) {
    (void) arg;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    while (1) {
        struct pcap_pkthdr header;
        const u_char *packet = pcap_next(handle, &header);

        if (packet) {
            struct iphdr *ip = (struct iphdr *)(packet + 14);  // Skip Ethernet header
            struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + (ip->ihl * 4));

            if (tcp->syn && tcp->ack) {
                printf("Port %d: OPEN (SYN-ACK)\n", ntohs(tcp->source));
            } else if (tcp->rst) {
                printf("Port %d: CLOSED (RST)\n", ntohs(tcp->source));
            }
        }
    }
    pcap_close(handle);
    return NULL;
}

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

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
void send_syn(int sock, struct sockaddr_in *target) {
    char packet[4096];
    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // IP/TCP headers web found examples modified to be checked later if something is missing 
    // IP header
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->id = htons(rand() % 65535);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = INADDR_ANY;  // kernel will fill this
    ip->daddr = target->sin_addr.s_addr;

    // TCP header
    tcp->source = htons(rand() % 65535);  // Random source port
    tcp->dest = target->sin_port;
    tcp->seq = htonl(rand() % 4294967295);
    tcp->ack_seq = 0;
    tcp->doff = 5;  // TCP header length (5 * 4 = 20 bytes)
    tcp->syn = 1;   // SYN flag
    tcp->window = htons(5840);
    tcp->check = 0;  //TODO: compute later
    tcp->urg_ptr = 0;

    //TODO: Compute checksum (pseudo-header + TCP header)
    tcp->check = compute_tcp_checksum(ip, tcp);

    // Send the packet
    sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
           (struct sockaddr *)target, sizeof(*target));
}

// Thread worker function

void *scan_thread(void *arg) {
    scan_thread_data *data = (scan_thread_data *)arg;
    t_config *config = data->config;
    
    printf("Thread %d: Scanning ports %d-%d\n", 
          data->thread_id, data->start_port, data->end_port - 1);

    for (int port_idx = data->start_port; port_idx < data->end_port; port_idx++) {
        int port = config->port_list[port_idx];
        struct servent *service = getservbyport(htons(port), "tcp");
        
        printf("config->scan_type_count = %d\n", config->scan_type_count);

        for (int scan_idx = 0; scan_idx < config->scan_type_count; scan_idx++) {
            const char *scan_type = config->scan_types[scan_idx];

            // printf("[Thread %d] Port %d (%s): %s scan - ",
            //       data->thread_id, port,
            //       service ? service->s_name : "unknown",
            //       scan_type);

            // Common scan preparation
            struct sockaddr_in target = {
                .sin_family = AF_INET,
                .sin_port = htons(port)
            };
            inet_pton(AF_INET, config->ip, &target.sin_addr);

            //different scan types
            // S -> SYN
            if (strcmp(scan_type, "S") == 0) {
                // SYN Scan implementation
                int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
                if (sock < 0) {
                    perror("socket(SYN)");
                    continue;
                }

                // int setsockopt(int socket, int level, int option_name,
                    // const void *option_value, socklen_t option_len);
                int one = 1;
                if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))) {
                    perror("setsockopt(IP_HDRINCL)");
                    close(sock);
                    continue;
                }
                    // Send SYN packet
                    send_syn(sock, &target);
                    
                /////////////////////////////////////////////
                // timeout + response handling (libpcap in another thread)
                pthread_t listner;
                struct timespec ts;
                int timeout_ms = *(int *)arg; // Get timeout from argument
            
                printf("scaner thread: Creating listner thread...\n");
                pthread_create(&listner, NULL, capture_responses, NULL);
            
                pthread_mutex_lock(&mutex);
            
                // Calculate absolute timeout time
                clock_gettime(CLOCK_REALTIME, &ts);
                ts.tv_sec += timeout_ms / 1000;
                ts.tv_nsec += (timeout_ms % 1000) * 1000000;
                if (ts.tv_nsec >= 1000000000) {
                    ts.tv_sec++;
                    ts.tv_nsec -= 1000000000;
                }
            
                // Wait for listner thread to finish with a timeout
                int ret = 0;
                while (!inner_thread_finished && ret == 0) {
                    ret = pthread_cond_timedwait(&cond_var, &mutex, &ts);
                }
                
                pthread_mutex_unlock(&mutex);
                /////////////////////////////////////////////////

                // TODO: implement the logic based on server respense
                
                close(sock);
                printf("SYN sent\n");
            }
            // TODO: other scan types (NULL, FIN, XMAS, ACK)
            // N -> NULL
            else if (strcmp(scan_type, "N") == 0){
                continue;
            }
            // A -> ACK
            else if (strcmp(scan_type, "A") == 0){
                continue;
            }
            // F -> FIN
            else if (strcmp(scan_type, "F") == 0){
                continue;
            }
            // X -> XMAS
            else if (strcmp(scan_type, "X") == 0){
                continue;
            }
            // U -> UDP
            else if (strcmp(scan_type, "U") == 0) {
                // UDP Scan implementation
                int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                if (sock < 0) {
                    perror("socket(UDP)");
                    continue;
                }
                
                // UDP scan logic
                if (connect(sock, (struct sockaddr *)&target, sizeof(target)) == 0) {
                    printf("UDP open\n");
                } else {
                    printf("UDP %s\n", errno == ECONNREFUSED ? "closed" : "filtered");
                }
                close(sock);
            }
            else {
                // printf("Scan type not implemented\n");
                continue;
            }
        }
    }
    return NULL;
}
