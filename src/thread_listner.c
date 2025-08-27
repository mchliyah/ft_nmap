#include "../include/ft_nmap.h"

const char *get_service_by_port(int port) {
    switch (port) {
        case 21: return "ftp";
        case 22: return "ssh";
        case 23: return "telnet";
        case 25: return "smtp";
        case 53: return "domain";
        case 80: return "http";
        case 110: return "pop3";
        case 143: return "imap";
        case 443: return "https";
        case 465: return "smtps";
        case 587: return "submission";
        case 853: return "domain-s";
        case 993: return "imaps";
        case 995: return "pop3s";
        case 1433: return "ms-sql-s";
        case 3306: return "mysql";
        case 3389: return "rdp";
        case 5432: return "postgresql";
        case 6379: return "redis";
        case 8080: return "http-proxy";
        case 8443: return "https-alt";
        case 27017: return "mongodb";
        default: return "unknown";
    }
}

const char *extract_service_from_payload(const u_char *payload, size_t payload_len, int port) {
    if (payload_len == 0) return NULL;
    
    size_t scan_len = payload_len > 1024 ? 1024 : payload_len;
    char *payload_str = malloc(scan_len + 1);
    if (!payload_str) return NULL;
    
    memcpy(payload_str, payload, scan_len);
    payload_str[scan_len] = '\0';

    for (size_t i = 0; i < scan_len; i++) {
        payload_str[i] = tolower(payload_str[i]);
    }
    
    const char *service = NULL;

    if (strstr(payload_str, "ssh-")) {
        service = "ssh";
    }
    else if (strstr(payload_str, "http/") || strstr(payload_str, "get ") || 
             strstr(payload_str, "post ") || strstr(payload_str, "host:") ||
             strstr(payload_str, "server:") || strstr(payload_str, "content-type:")) {
        service = "http";
    }
    else if (memcmp(payload, "\x16\x03", 2) == 0) {
        if (port == 443) service = "https";
        else if (port == 993) service = "imaps";
        else if (port == 995) service = "pop3s";
        else if (port == 465) service = "smtps";
        else if (port == 853) service = "domain-s";
        else service = "ssl";
    }
    else if (strstr(payload_str, "220") && (strstr(payload_str, "ftp") || 
             strstr(payload_str, "filezilla") || strstr(payload_str, "vsftpd"))) {
        service = "ftp";
    }
    else if (strstr(payload_str, "220") && (strstr(payload_str, "smtp") || 
             strstr(payload_str, "esmtp") || strstr(payload_str, "postfix"))) {
        service = "smtp";
    }
    else if (strstr(payload_str, "+ok") && strstr(payload_str, "pop3")) {
        service = "pop3";
    }
    else if (strstr(payload_str, "* ok") && strstr(payload_str, "imap")) {
        service = "imap";
    }
    else if (strstr(payload_str, "mysql")) {
        service = "mysql";
    }
    else if (strstr(payload_str, "postgres")) {
        service = "postgresql";
    }
    else if (strstr(payload_str, "redis")) {
        service = "redis";
    }
    else {
        service = get_service_by_port(port);
    }
    
    free(payload_str);
    return service;
}
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
    size_t tcplen = tcph->th_off * 4;
    const unsigned char *tcpdata = buffer + sizeof(struct ether_header) + iplen + tcplen;
    size_t data_len = header->caplen - (sizeof(struct ether_header) + iplen + tcplen);

    pthread_mutex_lock(&g_config.port_mutex);
    t_port *current = g_config.port_list;
    while (current) {

        // check header for service
        if (ntohs(tcph->source) == current->port)
        {
            if (tcph->syn && tcph->ack){
                current->state = STATE_OPEN;
                if (data_len > 0 && current->service == NULL) {
                    current->service = extract_service_from_payload(tcpdata, data_len, current->port);
                }
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
