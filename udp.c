#include "udp.h"
#include  "./include/verbose.h"

scanner_context_t *g_scanner_ctx = NULL;

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <target_ip> <ports> [interface]\n", argv[0]);
        printf("Example: %s 192.168.1.1 53,80,443,1000-2000 eth0\n", argv[0]);
        return 1;
    }

    // Setup signal handling
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    scanner_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    g_scanner_ctx = &ctx;

    ctx.target_ip = argv[1];
    ctx.thread_count = 10; // Default thread count
    
    // Parse port range
    if (parse_port_range(argv[2], &ctx.ports, &ctx.port_count) != 0) {
        fprintf(stderr, "Error parsing port range\n");
        return 1;
    }

    // Allocate results array
    ctx.results = calloc(ctx.port_count, sizeof(scan_result_t));
    if (!ctx.results) {
        fprintf(stderr, "Memory allocation failed\n");
        free(ctx.ports);
        return 1;
    }

    // Initialize results
    for (int i = 0; i < ctx.port_count; i++) {
        ctx.results[i].port = ctx.ports[i];
        ctx.results[i].status = PORT_UNKNOWN;
        strncpy(ctx.results[i].service_name, get_service_name(ctx.ports[i]), 
                sizeof(ctx.results[i].service_name) - 1);
    }

    // Initialize mutex
    if (pthread_mutex_init(&ctx.results_mutex, NULL) != 0) {
        fprintf(stderr, "Mutex initialization failed\n");
        cleanup_scanner(&ctx);
        return 1;
    }

    // Setup pcap listener
    const char *interface = (argc > 3) ? argv[3] : "any";
    if (setup_pcap_listener(interface, &ctx.pcap_handle) != 0) {
        fprintf(stderr, "Failed to setup packet capture\n");
        cleanup_scanner(&ctx);
        return 1;
    }

    printf("Starting UDP scan on %s for %d ports...\n", ctx.target_ip, ctx.port_count);
    gettimeofday(&ctx.scan_start_time, NULL);

    // Start listener thread
    pthread_t listener_thread;
    if (pthread_create(&listener_thread, NULL, packet_listener_thread, &ctx) != 0) {
        fprintf(stderr, "Failed to create listener thread\n");
        cleanup_scanner(&ctx);
        return 1;
    }

    // Start sender threads
    pthread_t *sender_threads = malloc(ctx.thread_count * sizeof(pthread_t));
    sender_thread_data_t *thread_data = malloc(ctx.thread_count * sizeof(sender_thread_data_t));
    
    int ports_per_thread = ctx.port_count / ctx.thread_count;
    int remaining_ports = ctx.port_count % ctx.thread_count;

    for (int i = 0; i < ctx.thread_count; i++) {
        thread_data[i].target_ip = ctx.target_ip;
        thread_data[i].thread_id = i;
        thread_data[i].raw_socket = create_raw_socket();
        
        if (thread_data[i].raw_socket < 0) {
            fprintf(stderr, "Failed to create raw socket for thread %d\n", i);
            continue;
        }

        int start_idx = i * ports_per_thread;
        int port_count = ports_per_thread + (i == ctx.thread_count - 1 ? remaining_ports : 0);
        
        thread_data[i].ports = &ctx.ports[start_idx];
        thread_data[i].port_count = port_count;

        if (pthread_create(&sender_threads[i], NULL, packet_sender_thread, &thread_data[i]) != 0) {
            fprintf(stderr, "Failed to create sender thread %d\n", i);
        }
    }

    // Wait for sender threads to complete
    for (int i = 0; i < ctx.thread_count; i++) {
        pthread_join(sender_threads[i], NULL);
        if (thread_data[i].raw_socket >= 0) {
            close(thread_data[i].raw_socket);
        }
    }

    // Wait for responses
    printf("Waiting for responses...\n");
    sleep(PACKET_TIMEOUT + 1);
    ctx.scan_complete = 1;

    // Wait for listener thread
    pthread_cancel(listener_thread);
    pthread_join(listener_thread, NULL);

    // Print results
    print_scan_results(&ctx);

    // Cleanup
    free(sender_threads);
    free(thread_data);
    cleanup_scanner(&ctx);

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

int send_udp_probe(int raw_socket, const char *target_ip, uint16_t port) {
    char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + 8];
    struct iphdr *ip_header = (struct iphdr *)packet;
    struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct iphdr));
    char *payload = packet + sizeof(struct iphdr) + sizeof(struct udphdr);

    memset(packet, 0, sizeof(packet));

    // Fill IP header (similar to nmap)
    ip_header->version = 4;
    ip_header->ihl = 5;
    ip_header->tos = 0;
    ip_header->tot_len = htons(sizeof(packet));
    ip_header->id = htons(rand() % 65535);
    ip_header->frag_off = htons(IP_DF);
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_UDP;
    ip_header->saddr = inet_addr("127.0.0.1"); // Will be set by kernel
    ip_header->daddr = inet_addr(target_ip);

    // Calculate IP checksum
    ip_header->check = 0;
    ip_header->check = calculate_checksum((uint16_t *)ip_header, sizeof(struct iphdr));

    // Fill UDP header
    udp_header->source = htons(rand() % 30000 + 32768);
    udp_header->dest = htons(port);
    udp_header->len = htons(sizeof(struct udphdr) + 8);
    udp_header->check = 0; // Let kernel calculate

    // Add some payload data (similar to nmap UDP probes)
    strcpy(payload, "nmap\x00");

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(target_ip);
    dest_addr.sin_port = htons(port);

    if (sendto(raw_socket, packet, sizeof(packet), 0, 
               (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        return -1;
    }

    return 0;
}

void *packet_sender_thread(void *arg) {
    sender_thread_data_t *data = (sender_thread_data_t *)arg;
    
    printf("Thread %d: Scanning %d ports\n", data->thread_id, data->port_count);
    
    for (int i = 0; i < data->port_count; i++) {
        if (send_udp_probe(data->raw_socket, data->target_ip, data->ports[i]) < 0) {
            fprintf(stderr, "Failed to send probe to port %d\n", data->ports[i]);
        }
        usleep(1000); // Small delay to avoid overwhelming target
    }
    
    printf("Thread %d: Completed sending probes\n", data->thread_id);
    return NULL;
}

void *packet_listener_thread(void *arg) {
    scanner_context_t *ctx = (scanner_context_t *)arg;
    
    printf("Starting packet listener...\n");
    
    // Start packet capture loop
    pcap_loop(ctx->pcap_handle, -1, packet_handler, (u_char *)ctx);
    
    return NULL;
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    scanner_context_t *ctx = (scanner_context_t *)user_data;
    struct iphdr *ip_header = (struct iphdr *)packet;
    
    if (ctx->scan_complete) return;

    // Check if packet is from our target
    struct in_addr src_addr;
    src_addr.s_addr = ip_header->saddr;
    
    if (strcmp(inet_ntoa(src_addr), ctx->target_ip) != 0) {
        return;
    }

    if (ip_header->protocol == IPPROTO_ICMP) {
        process_icmp_response(packet, pkthdr->len, ctx);
    } else if (ip_header->protocol == IPPROTO_UDP) {
        process_udp_response(packet, pkthdr->len, ctx);
    }
}

void process_icmp_response(const u_char *packet, int packet_len, scanner_context_t *ctx) {
    struct iphdr *ip_header = (struct iphdr *)packet;
    struct icmp_header *icmp_header = (struct icmp_header *)(packet + (ip_header->ihl * 4));
    
    // ICMP Port Unreachable indicates closed port
    if (icmp_header->type == ICMP_DEST_UNREACH && icmp_header->code == ICMP_PORT_UNREACH) {
        // Extract the original UDP header from ICMP payload
        struct iphdr *orig_ip = (struct iphdr *)((u_char *)icmp_header + 8);
        struct udphdr *orig_udp = (struct udphdr *)((u_char *)orig_ip + (orig_ip->ihl * 4));
        
        uint16_t port = ntohs(orig_udp->dest);
        
        pthread_mutex_lock(&ctx->results_mutex);
        for (int i = 0; i < ctx->port_count; i++) {
            if (ctx->results[i].port == port) {
                ctx->results[i].status = PORT_CLOSED;
                printf("the port closed\n");
                break;
            }
        }
        pthread_mutex_unlock(&ctx->results_mutex);
        
        printf("Port %d: closed (ICMP port unreachable)\n", port);
    }
}

void process_udp_response(const u_char *packet, int packet_len, scanner_context_t *ctx) {
    struct iphdr *ip_header = (struct iphdr *)packet;
    struct udphdr *udp_header = (struct udphdr *)(packet + (ip_header->ihl * 4));
    
    uint16_t port = ntohs(udp_header->source);
    
    pthread_mutex_lock(&ctx->results_mutex);
    for (int i = 0; i < ctx->port_count; i++) {
        if (ctx->results[i].port == port) {
            ctx->results[i].status = PORT_OPEN;
            printf("geting port open\n ");
            break;
        }
    }
    pthread_mutex_unlock(&ctx->results_mutex);
    
    printf("Port %d: open (UDP response received)\n", port);
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

int setup_pcap_listener(const char *interface, pcap_t **handle) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter_program;
    bpf_u_int32 subnet_mask, ip;
    
    if (pcap_lookupnet(interface, &ip, &subnet_mask, errbuf) == -1) {
        fprintf(stderr, "Could not get netmask for device %s: %s\n", interface, errbuf);
        ip = 0;
        subnet_mask = 0;
    }
    
    *handle = pcap_open_live(interface, SNAP_LEN, 1, 1000, errbuf);
    if (*handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", interface, errbuf);
        return -1;
    }
    
    if (pcap_compile(*handle, &filter_program, CAPTURE_FILTER, 0, ip) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", CAPTURE_FILTER, pcap_geterr(*handle));
        return -1;
    }
    
    if (pcap_setfilter(*handle, &filter_program) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", CAPTURE_FILTER, pcap_geterr(*handle));
        return -1;
    }
    
    printf("Packet capture setup complete on interface: %s\n", interface);
    return 0;
}

void print_scan_results(scanner_context_t *ctx) {
    struct timeval end_time;
    gettimeofday(&end_time, NULL);
    double scan_time = (end_time.tv_sec - ctx->scan_start_time.tv_sec) + 
                      (end_time.tv_usec - ctx->scan_start_time.tv_usec) / 1000000.0;
    
    printf("\n=== UDP Scan Results for %s ===\n", ctx->target_ip);
    printf("Scan completed in %.2f seconds\n\n", scan_time);
    
    int open_count = 0, closed_count = 0, filtered_count = 0;
    
    for (int i = 0; i < ctx->port_count; i++) {
        const char *status_str;
        switch (ctx->results[i].status) {
            case PORT_OPEN:
                status_str = "open";
                open_count++;
                break;
            case PORT_CLOSED:
                status_str = "closed";
                closed_count++;
                break;
            case PORT_FILTERED:
                status_str = "filtered";
                filtered_count++;
                break;
            default:
                status_str = "open|filtered";
                filtered_count++;
        }
        
        printf("%-6d/udp %-12s %s\n", 
               ctx->results[i].port, status_str, ctx->results[i].service_name);
    }
    
    printf("\nPorts scanned: %d\n", ctx->port_count);
    printf("Open: %d, Closed: %d, Filtered: %d\n", open_count, closed_count, filtered_count);
}

int parse_port_range(const char *port_str, uint16_t **ports, int *count) {
    // Simple implementation - supports comma-separated ports and ranges
    char *str_copy = strdup(port_str);
    char *token = strtok(str_copy, ",");
    uint16_t temp_ports[MAX_PORTS];
    int temp_count = 0;
    
    while (token != NULL && temp_count < MAX_PORTS) {
        if (strchr(token, '-')) {
            // Range format: start-end
            int start, end;
            if (sscanf(token, "%d-%d", &start, &end) == 2) {
                for (int i = start; i <= end && temp_count < MAX_PORTS; i++) {
                    temp_ports[temp_count++] = (uint16_t)i;
                }
            }
        } else {
            // Single port
            int port = atoi(token);
            if (port > 0 && port <= 65535) {
                temp_ports[temp_count++] = (uint16_t)port;
            }
        }
        token = strtok(NULL, ",");
    }
    
    *ports = malloc(temp_count * sizeof(uint16_t));
    if (!*ports) {
        free(str_copy);
        return -1;
    }
    
    memcpy(*ports, temp_ports, temp_count * sizeof(uint16_t));
    *count = temp_count;
    
    free(str_copy);
    return 0;
}

const char *get_service_name(uint16_t port) {
    switch (port) {
        case 53: return "dns";
        case 67: return "dhcp";
        case 68: return "dhcp-client";
        case 69: return "tftp";
        case 123: return "ntp";
        case 137: return "netbios-ns";
        case 138: return "netbios-dgm";
        case 161: return "snmp";
        case 162: return "snmptrap";
        case 514: return "syslog";
        case 1434: return "ms-sql-m";
        case 1812: return "radius";
        case 1813: return "radius-acct";
        default: return "unknown";
    }
}

void cleanup_scanner(scanner_context_t *ctx) {
    if (ctx->pcap_handle) {
        pcap_close(ctx->pcap_handle);
    }
    if (ctx->ports) {
        free(ctx->ports);
    }
    if (ctx->results) {
        free(ctx->results);
    }
    pthread_mutex_destroy(&ctx->results_mutex);
}

void signal_handler(int sig) {
    printf("\nReceived signal %d, cleaning up...\n", sig);
    if (g_scanner_ctx) {
        g_scanner_ctx->scan_complete = 1;
        cleanup_scanner(g_scanner_ctx);
    }
    exit(0);
}