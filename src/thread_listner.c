#include "../include/ft_nmap.h"

const char* find_interface_for_target(const char *target_ip) {
    struct ifaddrs *ifaddr, *ifa;
    uint32_t target = inet_addr(target_ip);
    char *best_iface = NULL;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return strdup("eth0"); // fallback
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;

        struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
        struct sockaddr_in *mask = (struct sockaddr_in *)ifa->ifa_netmask;

        if ((addr->sin_addr.s_addr & mask->sin_addr.s_addr) == 
            (target & mask->sin_addr.s_addr)) {
            best_iface = strdup(ifa->ifa_name);
            break;
        }
    }

    freeifaddrs(ifaddr);
    return best_iface ? best_iface : strdup("eth0");
}


void *capture_responses(void *arg) {
    capture_thread_args *args = (capture_thread_args *)arg;
    const char *interface = find_interface_for_target(args->config->ip);
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter[256];
    struct bpf_program fp;
    struct timeval start;
    int retry_count = 0;
    const int max_retries = 2;
    

    printf("starting capture on interface %s\n", interface);
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Could not open %s: %s\n", interface, errbuf);
        // free(interface);
        free(args);
        return NULL;
    }

    snprintf(filter, sizeof(filter), "tcp and dst port %d", ntohs(args->target.sin_port));
    
    if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Filter error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        // free(interface);
        free(args);
        return NULL;
    }

    gettimeofday(&start, NULL);

    while (retry_count < max_retries && args->state == STATE_WAITING) {
            struct pcap_pkthdr header;
            const u_char *packet = pcap_next(handle, &header);
    printf("checking packet \n");
        if (packet) {
            printf("\n=== Received Packet ===\n");
            printf("Packet length: %d bytes\n", header.len);
            printf("Timestamp: %ld.%06ld\n", header.ts.tv_sec, header.ts.tv_usec);

            // Verify minimum packet size (Ethernet + IP + TCP headers)
            if (header.len < 14 + 20 + 20) {
                printf("Packet too small (%d bytes)\n", header.len);
                continue;
            }

            // Ethernet header (first 14 bytes)
            printf("Ethernet Header:\n");
            printf("  Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
            printf("  Dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
            printf("  EtherType: 0x%04x\n", (packet[12] << 8) | packet[13]);

            // IP header (starts at byte 14)
            struct iphdr *ip = (struct iphdr *)(packet + 14);
            printf("\nIP Header:\n");
            printf("  Version: %d\n", ip->version);
            printf("  Header Length: %d bytes\n", ip->ihl * 4);
            printf("  TTL: %d\n", ip->ttl);
            printf("  Protocol: %d\n", ip->protocol);
            printf("  Source: %s\n", inet_ntoa(*(struct in_addr*)&ip->saddr));
            printf("  Destination: %s\n", inet_ntoa(*(struct in_addr*)&ip->daddr));

            // TCP header (starts after IP header)
            struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + (ip->ihl * 4));
            printf("\nTCP Header:\n");
            printf("  Source Port: %d\n", ntohs(tcp->source));
            printf("  Dest Port: %d\n", ntohs(tcp->dest));
            printf("  Seq Number: %u\n", ntohl(tcp->seq));
            printf("  Ack Number: %u\n", ntohl(tcp->ack_seq));
            printf("  Flags: [%s%s%s%s%s%s]\n",
                   tcp->syn ? "SYN " : "",
                   tcp->ack ? "ACK " : "",
                   tcp->fin ? "FIN " : "",
                   tcp->rst ? "RST " : "",
                   tcp->psh ? "PSH " : "",
                   tcp->urg ? "URG " : "");
            printf("  Window Size: %d\n", ntohs(tcp->window));
            printf("  Checksum: 0x%04x\n", ntohs(tcp->check));

            // Validate this is a response to our SYN
            if (ntohs(tcp->dest) == args->port && 
                tcp->ack && 
                ntohl(tcp->ack_seq) == args->expected_ack) {
                
                pthread_mutex_lock(&args->config->mutex);
                if (tcp->syn) {
                    args->state = STATE_OPEN;
                    printf("Port %d: OPEN (SYN-ACK)\n", args->port);
                } else if (tcp->rst) {
                    args->state = STATE_CLOSED;
                    printf("Port %d: CLOSED (RST)\n", args->port);
                }
                pthread_cond_signal(&args->config->cond);
                pthread_mutex_unlock(&args->config->mutex);
                break;
            }
    }

        // Check timeout
        struct timeval now;
        gettimeofday(&now, NULL);
        if ((now.tv_sec - start.tv_sec) > 1) { // 1 second per try
            retry_count++;
            gettimeofday(&start, NULL); // Reset timer
        }
        usleep(1000);
    }

    // Final state if no response
    if (args->state == STATE_WAITING) {
        pthread_mutex_lock(&args->config->mutex);
        args->state = STATE_FILTERED;
        printf("Port %d: FILTERED (no response)\n", args->port);
        pthread_cond_signal(&args->config->cond);
        pthread_mutex_unlock(&args->config->mutex);
    }

    pcap_close(handle);
    return NULL;
}