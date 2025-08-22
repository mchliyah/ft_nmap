#include "../include/ft_nmap.h"

void process_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *buffer)
{
    (void)user; // Unused parameter
    (void)header;

    struct ether_header *ethh = (struct ether_header *)buffer;
    struct ip *iph = (struct ip *)(buffer + sizeof(struct ether_header));
    struct tcphdr *tcph = NULL;
    u_short iplen;

    // Ensure the packet is an IP packet
    // puts("Processing packet...");
    if (ntohs(ethh->ether_type) != ETHERTYPE_IP)
    {
        printf("Non-IP packet captured, skipping...\n");
        return;
    }

    // Ensure the packet is a TCP packet
    if (iph->ip_p != IPPROTO_TCP)
    {
        printf("Non-TCP packet captured, skipping...\n");
        return;
    }

    // Validate IP header length
    iplen = iph->ip_hl * 4;
    if (iplen < 20)
    {
        printf("ERROR: Invalid IP header length (%d bytes), skipping packet...\n", iplen);
        return;
    }

    // Parse TCP header
    tcph = (struct tcphdr *)(buffer + sizeof(struct ether_header) + iplen);

    // Print debug information - fix inet_ntoa static buffer issue
    // char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
    // inet_ntop(AF_INET, &iph->ip_src, src_ip_str, INET_ADDRSTRLEN);
    // inet_ntop(AF_INET, &iph->ip_dst, dst_ip_str, INET_ADDRSTRLEN);
    // printf("IP Header 38 : src=%s, dst=%s, len=%d\n", src_ip_str, dst_ip_str, ntohs(iph->ip_len));

    // Process the packet
    pthread_mutex_lock(&g_config.mutex);
    t_port *current = g_config.port_list;
    while (current)
    {
        if (ntohs(tcph->source) == current->port)
        {
            // Print debug information - fix inet_ntoa static buffer issue
            // printf("TCP Header 46 : src_port=%d, dst_port=%d, seq=%u, ack_seq=%u, flags=0x%x\n",
            //        ntohs(tcph->source), ntohs(tcph->dest), ntohl(tcph->seq), ntohl(tcph->ack_seq),
            //        (tcph->syn << 1) | (tcph->ack << 4) | (tcph->fin << 0));

            if (tcph->syn && tcph->ack)
            {
                printf("Port %d: OPEN\n", current->port);
                current->state = STATE_OPEN;
            }
            else if (tcph->rst)
            {
                printf("Port %d: CLOSED\n", current->port);
                current->state = STATE_CLOSED;
            }
            else if (tcph->fin)
            {
                printf("Port %d: FILTERED\n", current->port);
                current->state = STATE_FILTERED;
            }
            // else
            // {
            //     printf("Port %d: UNKNOWN RESPONSE\n", current->port);
            // }
            // break; // Stop after finding the matching port
        }
        current = current->next;
    }
    pthread_mutex_unlock(&g_config.mutex);
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
    if (!interface)
    {
        fprintf(stderr, "No valid interface found for target IP %s\n", g_config.ip);
        return NULL;
    }
    // printf("Using interface: %s\n", interface);

    if (pcap_lookupnet(interface, &netmask, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Can't get netmask for device %s err: %s\n", interface, errbuf);
        exit(EXIT_FAILURE);
    }

    handle = pcap_open_live(interface, P_SIZE, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Could not open device %s: %s\n", interface, errbuf);
        return NULL;
    }

    // set filter to catch incoming packets not outgoing
    snprintf(filter_exp, 100, "tcp and src host %s and dst host %s", g_config.ip, g_config.src_ip);
    // snprintf(filter_exp, 100, "((tcp) and (dst host %s))", g_config.src_ip);
    // fprintf(stderr, "Using filter: %s\n\n", filter_exp);
    if (pcap_compile(handle, &fp, filter_exp, 0, netmask) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    pcap_freecode(&fp);

    int timeout_count = 0;
    while (g_config.scaner_on)
    {
        // printf("Waiting for packets...\n");
        int pd = pcap_dispatch(handle, -1, &process_packet, NULL);
        // printf("pcap_dispatch returned %d\n", pd);
        if (pd == 0)
        {
            timeout_count++;
            if (timeout_count >= 3)
            {
                printf("Listener timeout reached\n");
                break;
            }
        }
        else if (pd == -1)
        {
            pcap_perror(handle, "pcap_dispatch");
            break;
        }
        else
        {
            timeout_count = 0;
        }
    }

    printf("Global listener stopped.\n");
    pcap_close(handle);
    pthread_exit(NULL);
}
