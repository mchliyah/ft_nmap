#include "../include/ft_nmap.h"

void process_udp_response(const u_char *packet, int packet_len) {
    (void) packet_len;
    
    struct ether_header *ethh = (struct ether_header *)packet;
    struct ip *iph = (struct ip *)(packet + sizeof(struct ether_header));
    
    if (ntohs(ethh->ether_type) != ETHERTYPE_IP) return;
    
    unsigned short iplen = iph->ip_hl * 4;
    struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + iplen);
    
    uint16_t src_port = ntohs(udp_header->uh_sport);
    
    char response_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->ip_src), response_ip, INET_ADDRSTRLEN);
    
    if (strcmp(response_ip, g_config.ip) != 0) {
        return;
    }
    
    pthread_mutex_lock(&g_config.port_mutex);
    t_port *current = g_config.port_list;
    V_PRINT(1, "going to check udp packet");
    while (current) {
        if (current->port == src_port && strcmp(current->tcp_udp, "udp") == 0) {
            current->state = STATE_OPEN;
            current->to_print = true;
            V_PRINT(1, "Discovered open port %d/udp on %s (UDP response received)\n", 
                    current->port, g_config.ip);
            break;
        }
        current = current->next;
    }
    pthread_mutex_unlock(&g_config.port_mutex);
}

void process_icmp_response(const u_char *packet, int packet_len) {
    (void) packet_len;
    
    struct ether_header *ethh = (struct ether_header *)packet;
    struct ip *iph = (struct ip *)(packet + sizeof(struct ether_header));
    
    if (ntohs(ethh->ether_type) != ETHERTYPE_IP) return;
    
    unsigned short iplen = iph->ip_hl * 4;
    struct icmp *icmp_header = (struct icmp *)(packet + sizeof(struct ether_header) + iplen);
    
    if (icmp_header->icmp_type == ICMP_DEST_UNREACH && icmp_header->icmp_code == ICMP_PORT_UNREACH) {
        struct ip *orig_ip = (struct ip *)((u_char *)icmp_header + 8);
        unsigned short orig_iplen = orig_ip->ip_hl * 4;
        struct udphdr *orig_udp = (struct udphdr *)((u_char *)orig_ip + orig_iplen);
        
        uint16_t port = ntohs(orig_udp->uh_dport);
        
        pthread_mutex_lock(&g_config.port_mutex);
        t_port *current = g_config.port_list;
        while (current) {
            if (current->port == port && strcmp(current->tcp_udp, "udp") == 0) {
                current->state = STATE_CLOSED;
                current->to_print = true;
                V_PRINT(1, "Discovered closed port %d/udp on %s (ICMP port unreachable)\n", 
                        current->port, g_config.ip);
                break;
            }
            current = current->next;
        }
        pthread_mutex_unlock(&g_config.port_mutex);
    }
}

void process_tcp_packet(const struct pcap_pkthdr *header, const unsigned char *buffer, unsigned short iplen, struct ip *iph) {
    struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct ether_header) + iplen);
    size_t tcplen = tcph->th_off * 4;
    const unsigned char *tcpdata = buffer + sizeof(struct ether_header) + iplen + tcplen;
    size_t data_len = header->caplen - (sizeof(struct ether_header) + iplen + tcplen);

    uint8_t ttl = iph->ip_ttl;
    char reason_buffer[64];

    pthread_mutex_lock(&g_config.port_mutex);
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->ip_src), src_ip, INET_ADDRSTRLEN);

    t_ips *current_ip = g_config.ips;
    while (current_ip){
        if (strcmp(src_ip, current_ip->ip) == 0) {
            t_port *current = current_ip->port_list;
            while (current) {
                if (ntohs(tcph->source) == current->port && strcmp(current->tcp_udp, "tcp") == 0) {
                    if (tcph->syn && tcph->ack){
                        current->state = STATE_OPEN;
                        if (g_config.reason) {
                            snprintf(reason_buffer, sizeof(reason_buffer), "syn-ack ttl %d", ttl);
                            current->reason = strdup(reason_buffer);
                        }
                        V_PRINT(1, "Discovered open port %d/tcp on %s\n", 
                        current->port, current_ip->ip);
                        current->to_print = true;
                        if (data_len > 0 && current->service == NULL) {
                            current->service = extract_service_from_payload(tcpdata, data_len, current->port);
                            if (current->service) {
                                V_PRINT(2, "Service detection: port %d/tcp is %s\n", 
                                        current->port, current->service);
                            }
                        }
                    }
                    else if (tcph->rst){
                        current->state = STATE_CLOSED;
                        if (g_config.reason) {
                            snprintf(reason_buffer, sizeof(reason_buffer), "reset ttl %d", ttl);
                            current->reason = strdup(reason_buffer);
                        }
                        current->to_print = true;
                    }
                    else if (tcph->fin){
                        current->state = STATE_FILTERED;
                        if (g_config.reason) {
                            current->reason = strdup("no-response");
                        }
                        current->to_print = true;
                    }
                }
                current = current->next;
            }
        }
        current_ip = current_ip->next;
    }
    pthread_mutex_unlock(&g_config.port_mutex);
}

void process_packet(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *buffer) {
    (void)user;

    struct ether_header *ethh = (struct ether_header *)buffer;
    struct ip *iph = (struct ip *)(buffer + sizeof(struct ether_header));
    
    unsigned short iplen;
    g_config.packets_received++;
    
    if (ntohs(ethh->ether_type) != ETHERTYPE_IP) return;
    
    iplen = iph->ip_hl * 4;
    // V_PRINT(1, "packet recived %u  ", iplen);
    if (iplen < 20) return;
    
    if (iph->ip_p == IPPROTO_ICMP) process_icmp_response(buffer, header->caplen);
    else if (iph->ip_p == IPPROTO_UDP && g_config.scan_types.udp) process_udp_response(buffer, header->caplen);
    else if (iph->ip_p == IPPROTO_TCP) process_tcp_packet(header, buffer, iplen, iph);
}

pcap_t *set_pcap(void){

    bpf_u_int32 netmask;
    bpf_u_int32 mask;
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter_exp[100];
    pcap_t *handle;
    const char *interface = find_interface_for_target(g_config.ip);
    
    if (!interface) {
        fprintf(stderr, "No valid interface found for target IP %s\n", g_config.ip);
        return NULL;
    }

    if (pcap_lookupnet(interface, &netmask, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s err: %s\n", interface, errbuf);
        exit(EXIT_FAILURE);
    }

    handle = pcap_open_live(interface, P_SIZE, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", interface, errbuf);
        return NULL;
    }

    if (g_config.scan_types.udp) {
        snprintf(filter_exp, 100, "icmp or udp and host");
    } else {
        snprintf(filter_exp, 100, "tcp");
    }
    
    if (pcap_compile(handle, &fp, filter_exp, 0, netmask) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    pcap_freecode(&fp);

    V_PRINT(1, "Starting listener on interface %s\n", interface);
    V_PRINT(2, "Using filter: %s\n", filter_exp);

    return handle;
}

void *start_listner() {
    pcap_t *handle = set_pcap();
    int timeout_count = 0;

    while (!g_config.scan_complete) {
        int pd = pcap_dispatch(handle, -1, &process_packet, NULL);
        if (pd == 0)
        {
            timeout_count++;
            V_PRINT(3, "No packets received, timeout count: %d\n", timeout_count);
            if (timeout_count >= g_config.timeout)
            {
                V_PRINT(1, "No packets received for a while, listener exiting...\n");
                g_config.scan_complete = true;
                break;
            }
        }
        else if (pd == -1) {
            V_PRINT_ERR(1, "pcap_dispatch error: ");
            pcap_perror(handle, "pcap_dispatch");
            break;
        }
        else {
            V_PRINT(3, "Received %d packets\n", pd);
            timeout_count = 0;
        }
    }
    V_PRINT(1, "Listener stopped\n");
    pcap_close(handle);
    pthread_exit(NULL);
}