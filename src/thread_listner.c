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
        if (code >= 1 && code <= 13) { // Valid RADIUS codes
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
void process_udp_packet(struct ip *iph, const struct pcap_pkthdr *header, const unsigned char *buffer) {
    (void)header;
    
    struct udphdr *udph = (struct udphdr *)((char *)iph + (iph->ip_hl * 4));
    uint16_t sport = ntohs(udph->uh_sport);  // Source port of response
    uint16_t dport = ntohs(udph->uh_dport);  // Destination port of response
    uint8_t ttl = iph->ip_ttl;
    char reason_buffer[64];
    
    // Get source IP of the response
    char *response_ip = inet_ntoa(iph->ip_src);
    
    PRINT_DEBUG("Received UDP response from %s:%d to our port %d\n", 
                response_ip, sport, dport);
    
    // CRITICAL: Only process responses from our target IP
    if (strcmp(response_ip, g_config.ip) != 0) {
        PRINT_DEBUG("Ignoring response from %s (target is %s)\n", 
                    response_ip, g_config.ip);
        return;
    }
    
    pthread_mutex_lock(&g_config.port_mutex);
    t_port *current = g_config.port_list;
    while (current) {
        // Check if this response is for one of our scanned ports
        // The source port of the response should match the port we sent to
        if (sport == current->port && strcmp(current->tcp_udp, "udp") == 0) {
            current->state = STATE_OPEN;
            if (g_config.reason) {
                snprintf(reason_buffer, sizeof(reason_buffer), "udp-response ttl %d", ttl);
                current->reason = strdup(reason_buffer);
            }
            V_PRINT(1, "Discovered open port %d/udp on %s\n", current->port, g_config.ip);
            current->to_print = true;
            
            // Try to extract service information from UDP payload
            const unsigned char *udp_payload = buffer + sizeof(struct ether_header) + 
                                              (iph->ip_hl * 4) + sizeof(struct udphdr);
            size_t payload_len = ntohs(udph->uh_ulen) - sizeof(struct udphdr);
            
            if (payload_len > 0 && current->service == NULL) {
                current->service = extract_udp_service_from_payload(udp_payload, payload_len, current->port);
                if (current->service) {
                    V_PRINT(2, "Service detection: port %d/udp is %s\n", 
                            current->port, current->service);
                }
            }
            break;
        }
        current = current->next;
    }
    pthread_mutex_unlock(&g_config.port_mutex);
}

void process_icmp_packet(struct ip *iph, const struct pcap_pkthdr *header)
{
    (void)header;
    
    struct icmp *icmph = (struct icmp *)((char *)iph + (iph->ip_hl * 4));
    
    if (icmph->icmp_type == ICMP_UNREACH) {
        struct ip *orig_iph = (struct ip *)((char *)icmph + 8);
        if (orig_iph->ip_p == IPPROTO_UDP && icmph->icmp_code == ICMP_UNREACH_PORT) {
            struct udphdr *orig_udph = (struct udphdr *)((char *)orig_iph + (orig_iph->ip_hl * 4));
            uint16_t target_port = ntohs(orig_udph->uh_dport);
            uint8_t ttl = iph->ip_ttl;
            char reason_buffer[64];
            
            pthread_mutex_lock(&g_config.port_mutex);
            t_port *current = g_config.port_list;
            while (current) {
                if (current->port == target_port && strcmp(current->tcp_udp, "udp") == 0) {
                    current->state = STATE_CLOSED;
                    if (g_config.reason) {
                        snprintf(reason_buffer, sizeof(reason_buffer), "port-unreach ttl %d", ttl);
                        current->reason = strdup(reason_buffer);
                    }
                    current->to_print = true;
                    V_PRINT(1, "Discovered closed port %d/udp on %s (ICMP port unreachable)\n", 
                            current->port, g_config.ip);
                    break;
                }
                current = current->next;
            }
            pthread_mutex_unlock(&g_config.port_mutex);
        }
        else if (orig_iph->ip_p == IPPROTO_UDP && 
                (icmph->icmp_code == ICMP_UNREACH_HOST || 
                 icmph->icmp_code == ICMP_UNREACH_NET ||
                 icmph->icmp_code == ICMP_UNREACH_HOST_PROHIB ||
                 icmph->icmp_code == ICMP_UNREACH_NET_PROHIB)) {
            struct udphdr *orig_udph = (struct udphdr *)((char *)orig_iph + (orig_iph->ip_hl * 4));
            uint16_t target_port = ntohs(orig_udph->uh_dport);
            uint8_t ttl = iph->ip_ttl;
            char reason_buffer[64];
            
            pthread_mutex_lock(&g_config.port_mutex);
            t_port *current = g_config.port_list;
            while (current) {
                if (current->port == target_port && strcmp(current->tcp_udp, "udp") == 0) {
                    current->state = STATE_FILTERED;
                    if (g_config.reason) {
                        const char *icmp_reason;
                        switch (icmph->icmp_code) {
                            case ICMP_UNREACH_HOST: icmp_reason = "host-unreach"; break;
                            case ICMP_UNREACH_NET: icmp_reason = "net-unreach"; break;
                            case ICMP_UNREACH_HOST_PROHIB: icmp_reason = "host-prohib"; break;
                            case ICMP_UNREACH_NET_PROHIB: icmp_reason = "net-prohib"; break;
                            default: icmp_reason = "admin-prohib";
                        }
                        snprintf(reason_buffer, sizeof(reason_buffer), "%s ttl %d", icmp_reason, ttl);
                        current->reason = strdup(reason_buffer);
                    }
                    current->to_print = true;
                    V_PRINT(1, "Discovered filtered port %d/udp on %s (ICMP %s)\n", 
                            current->port, g_config.ip, reason_buffer);
                    break;
                }
                current = current->next;
            }
            pthread_mutex_unlock(&g_config.port_mutex);
        }
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

void process_packet(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *buffer)
{
    (void)user;

    struct ether_header *ethh = (struct ether_header *)buffer;
    struct ip *iph = (struct ip *)(buffer + sizeof(struct ether_header));
    
    unsigned short iplen;
    g_config.packets_received++;
    
    if (ntohs(ethh->ether_type) != ETHERTYPE_IP) {
        PRINT_DEBUG("Non-IP packet captured, skipping...\n");
        return;
    }
    
    iplen = iph->ip_hl * 4;
    if (iplen < 20) {
        PRINT_DEBUG("Invalid IP header length, skipping...\n");
        return;
    }

    if (iph->ip_p == IPPROTO_ICMP) {
        process_icmp_packet(iph, header);
    }
    else if (iph->ip_p == IPPROTO_UDP && g_config.scan_types.udp) {
        process_udp_packet(iph, header, buffer);
    }
    else if (iph->ip_p == IPPROTO_TCP) {
        process_tcp_packet(header, buffer, iplen, iph);
    }
    else {
        PRINT_DEBUG("Unhandled protocol %d, skipping...\n", iph->ip_p);
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
        snprintf(filter_exp, 100, "(tcp or icmp or udp) and host %s", g_config.ip);
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

//     const char *interface = find_interface_for_target(g_config.ip);
//     if (!interface) {
//         fprintf(stderr, "No valid interface found for target IP %s\n", g_config.ip);
//         return NULL;
//     }

//     if (pcap_lookupnet(interface, &netmask, &mask, errbuf) == -1) {
//         fprintf(stderr, "Can't get netmask for device %s err: %s\n", interface, errbuf);
//         exit(EXIT_FAILURE);
//     }

//     handle = pcap_open_live(interface, P_SIZE, 1, 1000, errbuf);
//     if (handle == NULL) {
//         fprintf(stderr, "Could not open device %s: %s\n", interface, errbuf);
//         return NULL;
//     }

//     // Create filter based on scan types
//     if (g_config.scan_types.udp) {
//         // For UDP scans, we need both ICMP (for closed ports) and UDP (for open ports) 
//         snprintf(filter_exp, 100, "(tcp or icmp or udp) and host %s", g_config.ip);
//     } else {
//         // For TCP scans only
//         snprintf(filter_exp, 100, "tcp and host %s", g_config.ip);
//     }
    
//     if (pcap_compile(handle, &fp, filter_exp, 0, netmask) == -1) {
//         fprintf(stderr, "Couldn't parse filter %s: %s\n",
//                 filter_exp, pcap_geterr(handle));
//         exit(EXIT_FAILURE);
//     }
//     if (pcap_setfilter(handle, &fp) == -1) {
//         fprintf(stderr, "Couldn't install filter %s: %s\n",
//                 filter_exp, pcap_geterr(handle));
//         exit(EXIT_FAILURE);
//     }
//     pcap_freecode(&fp);

//     V_PRINT(1, "Starting listener on interface %s\n", interface);
//     V_PRINT(2, "Using filter: %s\n", filter_exp);
//     int timeout_count = 0;
//     while (1) {
//         int pd = pcap_dispatch(handle, -1, &process_packet, NULL);
//         if (pd == 0)
//         {
//             timeout_count++;
//             V_PRINT(3, "No packets received, timeout count: %d\n", timeout_count);
//             if (timeout_count >= g_config.timeout)
//             {
//                 V_PRINT(1, "No packets received for a while, listener exiting...\n");
//                 break;
//             }
//         }
//         else if (pd == -1) {
//             V_PRINT_ERR(1, "pcap_dispatch error: ");
//             pcap_perror(handle, "pcap_dispatch");
//             break;
//         }
//         else {
//             V_PRINT(3, "Received %d packets\n", pd);
//             timeout_count = 0;
//         }
//     }
//     V_PRINT(1, "Listener stopped\n");
//     pcap_close(handle);
//     pthread_exit(NULL);
// }