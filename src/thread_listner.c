#include "../include/ft_nmap.h"


struct tcphdr *tcph;

char *extract_udp_service_from_payload(const unsigned char *payload, size_t payload_len, uint16_t port) {
    if (!payload || payload_len == 0) {
        return NULL;
    }

    if (port == 53 && payload_len >= 12) {
        if (payload[2] & 0x80) {
            return strdup("dns");
        }
    }

    else if ((port == 67 || port == 68) && payload_len >= 240) {
        if (payload_len > 240 && 
            payload[236] == 0x63 && payload[237] == 0x82 && 
            payload[238] == 0x53 && payload[239] == 0x63) {
            return strdup("dhcp");
        }
    }

    else if (port == 161 && payload_len >= 2) {
        if (payload[0] == 0x30) {
            return strdup("snmp");
        }
    }

    else if (port == 123 && payload_len >= 48) {
        uint8_t version = (payload[0] >> 3) & 0x07;
        uint8_t mode = payload[0] & 0x07;
        if (version >= 1 && version <= 4 && mode >= 1 && mode <= 5) {
            return strdup("ntp");
        }
    }

    else if (port == 137 && payload_len >= 12) {
        if (payload[2] & 0x80) {
            return strdup("netbios-ns");
        }
    }
    else if (port == 69 && payload_len >= 4) {
        uint16_t opcode = (payload[0] << 8) | payload[1];
        if (opcode >= 1 && opcode <= 5) {
            return strdup("tftp");
        }
    }

    else if (port == 111 && payload_len >= 28) {
        uint32_t msg_type = (payload[4] << 24) | (payload[5] << 16) | (payload[6] << 8) | payload[7];
        uint32_t rpc_version = (payload[8] << 24) | (payload[9] << 16) | (payload[10] << 8) | payload[11];
        if (msg_type == 1 && rpc_version == 2) {
            return strdup("rpcbind");
        }
    }

    else if (port == 1434 && payload_len > 0) {
        if (payload[0] == 0x05) {
            return strdup("ms-sql-m");
        }
    }
    else if ((port == 1812 || port == 1813) && payload_len >= 20) {
        uint8_t code = payload[0];
        if (code >= 1 && code <= 13) {
            return strdup("radius");
        }
    }
    
    else if (port == 5060 && payload_len > 8) {
        if (strncmp((char*)payload, "SIP/2.0", 7) == 0) {
            return strdup("sip");
        }
    }

    else {
        if (payload_len > 4 && strncmp((char*)payload, "HTTP", 4) == 0) {
            return strdup("http");
        }
        if (payload_len > 3 && isdigit(payload[0]) && isdigit(payload[1]) && isdigit(payload[2])) {
            return strdup("ftp");
        }
        
        if (payload_len > 4 && strncmp((char*)payload, "SSH-", 4) == 0) {
            return strdup("ssh");
        }
    }

    return NULL;
}


void process_udp_response(const u_char *packet, int packet_len) {
    (void) packet_len;
    
    struct ether_header *ethh = (struct ether_header *)packet;
    struct ip *iph = (struct ip *)(packet + sizeof(struct ether_header));
    
    if (ntohs(ethh->ether_type) != ETHERTYPE_IP) return;
    
    unsigned short iplen = iph->ip_hl * 4;
    struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + iplen);
    
    uint16_t src_port = ntohs(udp_header->uh_sport);
    uint16_t dst_port = ntohs(udp_header->uh_dport);
    
    char response_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->ip_src), response_ip, INET_ADDRSTRLEN);
    
    printf("erspense ip : %s and port %u\n", response_ip, src_port);
    printf("g_config ip : %s and port %u \n", g_config.ip, dst_port);
    
    if (strcmp(response_ip, g_config.ip) != 0) {
        return;
    }
    
    pthread_mutex_lock(&g_config.port_mutex);
    t_port *current = g_config.port_list;
    V_PRINT(1, "going to check udp packet");
    while (current) {
        printf("curent port : %d and src poer %d and curent tcp udp %s \n", current->port, src_port, current->tcp_udp);
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
    tcph = (struct tcphdr *)(buffer + sizeof(struct ether_header) + iplen);
    size_t tcplen = tcph->th_off * 4;
    const unsigned char *tcpdata = buffer + sizeof(struct ether_header) + iplen + tcplen;
    size_t data_len = header->caplen - (sizeof(struct ether_header) + iplen + tcplen);

    uint8_t ttl = iph->ip_ttl;
    char reason_buffer[64];

    pthread_mutex_lock(&g_config.port_mutex);
    t_port *current = g_config.port_list;
    while (current) {
        if (ntohs(tcph->source) == current->port && strcmp(current->tcp_udp, "tcp") == 0)
        {
            if (tcph->syn && tcph->ack){
                current->state = STATE_OPEN;
                if (g_config.reason) {
                    snprintf(reason_buffer, sizeof(reason_buffer), "syn-ack ttl %d", ttl);
                    current->reason = strdup(reason_buffer);
                }
                V_PRINT(1, "Discovered open port %d/tcp on %s\n", 
                        current->port, g_config.ip);
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
    V_PRINT(1, "packet recived %u  ", iplen);
    if (iplen < 20) return;
    
    if (iph->ip_p == IPPROTO_ICMP) {
        struct icmp *icmp_hdr = (struct icmp *)(buffer + (iph->ip_hl * 4));
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        
        strcpy(src_ip, inet_ntoa(iph->ip_src));
        strcpy(dst_ip, inet_ntoa(iph->ip_dst));
        
        PRINT_DEBUG("ICMP: %s -> %s, Type: %d, Code: %d\n", 
               src_ip, dst_ip,
               icmp_hdr->icmp_type, icmp_hdr->icmp_code);
        process_icmp_response(buffer, header->caplen);
    }
    else if (iph->ip_p == IPPROTO_UDP && g_config.scan_types.udp) {
        struct udphdr *udp_hdr = (struct udphdr *)(buffer + (iph->ip_hl * 4));
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        
        strcpy(src_ip, inet_ntoa(iph->ip_src));
        strcpy(dst_ip, inet_ntoa(iph->ip_dst));
        
        PRINT_DEBUG("UDP: %s:%d -> %s:%d, Length: %d\n", 
               src_ip, ntohs(udp_hdr->uh_sport),
               dst_ip, ntohs(udp_hdr->uh_dport),
               ntohs(udp_hdr->uh_ulen));
        process_udp_response(buffer, header->caplen);
    } 
    else if (iph->ip_p == IPPROTO_TCP) { 
        struct tcphdr *tcp_hdr = (struct tcphdr *)(buffer + (iph->ip_hl * 4));
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        
        strcpy(src_ip, inet_ntoa(iph->ip_src));
        strcpy(dst_ip, inet_ntoa(iph->ip_dst));
        
        PRINT_DEBUG("TCP: %s:%d -> %s:%d\n", 
               src_ip, ntohs(tcp_hdr->th_sport),
               dst_ip, ntohs(tcp_hdr->th_dport));
        process_tcp_packet(header, buffer, iplen, iph);
    }
}

void *start_listner()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    bpf_u_int32 netmask;
    bpf_u_int32 mask;
    char filter_exp[100];
    struct bpf_program fp;

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
        snprintf(filter_exp, 100, "icmp or udp and host %s", g_config.ip);
    } else {
        snprintf(filter_exp, 100, "tcp and host %s", g_config.ip);
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
    int timeout_count = 0;
    while (1) {
        int pd = pcap_dispatch(handle, -1, &process_packet, NULL);
        if (pd == 0)
        {
            timeout_count++;
            V_PRINT(3, "No packets received, timeout count: %d\n", timeout_count);
            if (timeout_count >= g_config.timeout)
            {
                V_PRINT(1, "No packets received for a while, listener exiting...\n");
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