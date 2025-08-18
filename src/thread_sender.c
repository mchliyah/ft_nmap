#include "../include/ft_nmap.h"


void init_scan() {
    srand(time(NULL));
}

void send_syn(int sock, struct sockaddr_in *target, const char *src_ip, int dest_port) {
    char datagram[4096] = {0};
    struct ip *ip = (struct ip *)datagram;
    struct tcphdr *tcp = (struct tcphdr *)(datagram + sizeof(struct ip));
    struct pseudo_header psh;

    set_ip_header(ip, src_ip, target);
    set_tcp_header(tcp, SCAN_SYN);

    // Add TCP options (MSS)
    uint8_t *options = (uint8_t *)(tcp + 1);
    options[0] = 0x02;  // MSS option kind
    options[1] = 0x04;  // Length
    *(uint16_t *)(options + 2) = htons(1460);  // MSS value

    // ip->check = csum((unsigned short *)datagram, sizeof(struct ip) >> 1);
    // tcp->source = htons(src_port);
    tcp->dest = htons(dest_port);

    // Build pseudo-header for TCP checksum
    psh.source_address = inet_addr(src_ip);
    psh.dest_address = ip->ip_dst.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));
    
    memcpy(&psh.tcp, tcp, sizeof(struct tcphdr));

    // Calculate TCP checksum
    tcp->check = csum((unsigned short *)&psh, sizeof(struct pseudo_header));
    

    // Send packet
    if (sendto(sock, datagram, sizeof(struct ip) + sizeof(struct tcphdr), 0,
               (struct sockaddr *)target, sizeof(*target)) < 0) {
        perror("sendto");
    }
}



void *scan_thread(void *arg) {
    scan_thread_data *data = (scan_thread_data *)arg;
    const char *src_ip = get_interface_ip(data->config->ip);

    printf("Thread %d: scanning ports %d to %d\n", 
           data->thread_id, 
           data->config->port_list[data->start_port],
           data->config->port_list[data->end_port - 1]);

    // Send SYN packets for assigned port range
    for (int i = data->start_port; i < data->end_port && !data->config->scan_complete; i++) {
        // Check for timeout before each port scan
        printf("curent port : %d \n", i);
        if (data->config->scan_start_time > 0 && (time(NULL) - data->config->scan_start_time) > 30) {
            printf("Thread %d: Scan timeout reached during port scanning\n", data->thread_id);
            break;
        }

        int port = data->config->port_list[i];
        
        struct sockaddr_in target = {
            .sin_family = AF_INET,
            .sin_port = htons(port),
            .sin_addr = { .s_addr = inet_addr(data->config->ip) }
        };
        // create socket 
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0) {
            perror("socket");
            continue;
        }
        // headers information
        int one = 1;
        if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))) {
            perror("setsockopt");
            close(sock);
            continue;
        }
        
        // Send SYN packet with MSS option
        send_syn(sock, &target, src_ip, port);
        close(sock);
        
        // Small delay to avoid flooding
        usleep(1000); // 1ms delay between packets
        
        // Check if we should stop scanning (open port found)
        if (data->config->scan_complete) {
            printf("Thread %d: Scan completed - open port found\n", data->thread_id);
            break;
        }
    }

    printf("Thread %d: finished sending packets\n", data->thread_id);
    return NULL;
}
