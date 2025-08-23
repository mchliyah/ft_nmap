#include "../include/ft_nmap.h"

// char *get_service_name(int port)
// {
//     // This function should return the service name associated with the given port
//     // For now, we'll just return a placeholder string
//     switch (port) {
//         case 22:  return "SSH";
//         case 80:  return "HTTP";
//         case 443: return "HTTPS";
//         default:  return "UNKNOWN";
//     }
// }

void process_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *buffer)
{
    (void)user;
    (void)header;

    struct ether_header *ethh = (struct ether_header *)buffer;
    struct ip *iph = (struct ip *)(buffer + sizeof(struct ether_header));
    struct tcphdr *tcph = NULL;
    u_short iplen;

    if (ntohs(ethh->ether_type) != ETHERTYPE_IP) {
        printf("Non-IP packet captured, skipping...\n");
        return;
    }
    if (iph->ip_p != IPPROTO_TCP) {
        printf("Non-TCP packet captured, skipping...\n");
        return;
    }
    iplen = iph->ip_hl * 4;
    if (iplen < 20) {
        printf("ERROR: Invalid IP header length (%d bytes), skipping packet...\n", iplen);
        return;
    }

    tcph = (struct tcphdr *)(buffer + sizeof(struct ether_header) + iplen);
    pthread_mutex_lock(&g_config.port_mutex);
    t_port *current = g_config.port_list;
    while (current) {

        // check header for service
        if (ntohs(tcph->source) == current->port)
        {
            if (tcph->syn && tcph->ack){
                current->state = STATE_OPEN;
            }
            else if (tcph->rst){
                current->state = STATE_CLOSED;
            }
            else if (tcph->fin){
                current->state = STATE_FILTERED;
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

    snprintf(filter_exp, 100, "tcp and src host %s and dst host %s", g_config.ip, g_config.src_ip);
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

    int timeout_count = 0;
    while (1) {
        int pd = pcap_dispatch(handle, -1, &process_packet, NULL); // multiple packets processed
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
