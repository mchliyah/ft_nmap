#include "../include/ft_nmap.h"


void process_packet(unsigned char *buffer, t_config *config) {
    struct ip *ip = (struct ip *)buffer;
    if (ip->ip_v != 4) {
        printf("Not an IPv4 packet, skipping...\n");
        return;
    }

    unsigned short iplen = ip->ip_hl * 4;
    struct tcphdr *tcph;
    memset(&tcph, 0, sizeof(tcph));
    tcph = (struct tcphdr *)(buffer + iplen);

    printf("syn %d\n", tcph->syn);
    printf("ack %d\n", tcph->ack);
    printf("ack %d\n", tcph->rst);    
    
    if (tcph->syn && tcph->ack) {
        printf("Port %d: OPEN\n", ntohs(tcph->source));
        (void) config;
        // Signal that we found an open port and can stop scanning
        // config->scan_complete = 1;
        // config->scaner_on = 0;
    } else if (tcph->rst) {
        printf("Port %d: CLOSED\n", ntohs(tcph->source));
    }
}


void *start_listner(void *arg) {
    t_config *config = (t_config *)arg;
    int sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw < 0) {
        perror("Sniffer socket failed");
        return NULL;
    }

    // Set socket timeout for recvfrom
    struct timeval timeout;
    timeout.tv_sec = 3;  // 1 second timeout
    timeout.tv_usec = 0;
    if (setsockopt(sock_raw, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt timeout failed");
    }

    unsigned char buffer[65536];
    struct sockaddr saddr;
    socklen_t saddr_size = sizeof(saddr);

    config->scaner_on = 1;
    printf("Global listener started...\n");
    memset(buffer, 0, sizeof(buffer));
    while (1) {
        // Check for overall scan timeout (30 seconds)
        int data_size = recvfrom(sock_raw, buffer, sizeof(buffer), 0, &saddr, &saddr_size);
        
        // printf("buffer : %s\n", buffer);
        if (config->scan_start_time > 0 && (time(NULL) - config->scan_start_time) > 30) {
            printf("Global listener: Scan timeout reached (30 seconds)\n");
            config->scaner_on = 0;
            // config->scan_complete = 1;
            break;
        }

        if (data_size < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {

                // Timeout occurred, continue loop to check other conditions
                continue;
            }
            if (config->scaner_on) perror("recvfrom failed");
            break;
        }
        process_packet(buffer, config);
    }
    
    printf("Global listener stopped.\n");
    close(sock_raw);
    return NULL;
}
