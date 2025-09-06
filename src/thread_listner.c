#include "../include/ft_nmap.h"

void process_icmp_packet(struct ip *iph, const struct pcap_pkthdr *header)
{
    (void)header;
    
    struct icmp *icmph = (struct icmp *)((char *)iph + (iph->ip_hl * 4));
    
    // We're interested in ICMP Destination Unreachable messages
    if (icmph->icmp_type == ICMP_UNREACH && icmph->icmp_code == ICMP_UNREACH_PORT) {
        // The ICMP packet contains the original IP header and first 8 bytes of the original UDP packet
        struct ip *orig_iph = (struct ip *)((char *)icmph + 8);
        struct udphdr *orig_udph = (struct udphdr *)((char *)orig_iph + (orig_iph->ip_hl * 4));
        
        uint16_t target_port = ntohs(orig_udph->uh_dport);
        uint8_t ttl = iph->ip_ttl;
        char reason_buffer[64];
        
        pthread_mutex_lock(&g_config.port_mutex);
        t_port *current = g_config.port_list;
        while (current) {
            if (current->port == target_port) {
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
}

void process_packet(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *buffer)
{
    (void)user;
    (void)header;

    struct ether_header *ethh = (struct ether_header *)buffer;
    struct ip *iph = (struct ip *)(buffer + sizeof(struct ether_header));
    struct tcphdr *tcph = NULL;
    unsigned short iplen;
    g_config.packets_received++;
    if (ntohs(ethh->ether_type) != ETHERTYPE_IP) {
        printf("Non-IP packet captured, skipping...\n");
        return;
    }
    
    // Handle different protocols based on scan type
    if (g_config.scan_types.udp && iph->ip_p == IPPROTO_ICMP) {
        // Handle ICMP responses for UDP scans
        process_icmp_packet(iph, header);
        return;
    }
    else if (iph->ip_p != IPPROTO_TCP) {
        printf("Non-TCP packet captured, skipping...\n");
        return;
    }
    iplen = iph->ip_hl * 4;
    if (iplen < 20) {
        printf("ERROR: Invalid IP header length (%d bytes), skipping packet...\n", iplen);
        return;
    }

    tcph = (struct tcphdr *)(buffer + sizeof(struct ether_header) + iplen);
    size_t tcplen = tcph->th_off * 4;
    const unsigned char *tcpdata = buffer + sizeof(struct ether_header) + iplen + tcplen;
    size_t data_len = header->caplen - (sizeof(struct ether_header) + iplen + tcplen);

    // Extract TTL from IP header for reason detection
    uint8_t ttl = iph->ip_ttl;
    char reason_buffer[64];

    pthread_mutex_lock(&g_config.port_mutex);
    t_port *current = g_config.port_list;
    while (current) {

        // check header for service
        if (ntohs(tcph->source) == current->port)
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

    snprintf(filter_exp, 100, "%s and host %s", 
             g_config.scan_types.udp ? "(tcp or icmp)" : "tcp", 
             g_config.ip); //filter to get needed packets
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
