#include "../include/ft_nmap.h"

// void *capture_responses(void *arg) {
//     capture_thread_args *args = (capture_thread_args *)arg;
//     const char *interface = find_interface_for_target(args->config->ip);
//     char errbuf[PCAP_ERRBUF_SIZE];
//     char filter[512];
//     struct bpf_program fp;
//     struct timeval start, now;
//     const double timeout_seconds = 3.0;
    
//     printf("starting capture on interface %s for port %d\n", interface, args->port);
    
//     pcap_t *handle = pcap_open_live(interface, 65536, 1, 1, errbuf);
//     if (!handle) {
//         fprintf(stderr, "Could not open %s: %s\n", interface, errbuf);
//         free((void*)interface);
//         free(args);
//         return NULL;
//     }

//     const char *src_ip = get_interface_ip(args->config->ip);
//     snprintf(filter, sizeof(filter), 
//              "tcp and src host %s and dst host %s and dst port %d",
//              args->config->ip, src_ip, args->src_port);
    
//     if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
//         pcap_setfilter(handle, &fp) == -1) {
//         fprintf(stderr, "Filter error: %s\n", pcap_geterr(handle));
//         pcap_close(handle);
//         free((void*)interface);
//         free(args);
//         return NULL;
//     }

//     printf("Using filter: %s\n", filter);

//     if (pcap_setnonblock(handle, 1, errbuf) == -1) {
//         fprintf(stderr, "Could not set non-blocking mode: %s\n", errbuf);
//     }

//     gettimeofday(&start, NULL);

//     while (args->state == STATE_WAITING) {
//         struct pcap_pkthdr header;
//         const u_char *packet = pcap_next(handle, &header);
        
//         gettimeofday(&now, NULL);
//         double elapsed = (now.tv_sec - start.tv_sec) + 
//                         (now.tv_usec - start.tv_usec) / 1000000.0;
        
//         if (elapsed > timeout_seconds) {
//             pthread_mutex_lock(&args->config->mutex);
//             if (args->state == STATE_WAITING) {
//                 args->state = STATE_FILTERED;
//                 printf("Port %d: FILTERED (timeout after %.1fs)\n", args->port, elapsed);
//                 pthread_cond_signal(&args->config->cond);
//             }
//             pthread_mutex_unlock(&args->config->mutex);
//             break;
//         }
        
//         if (packet) {
//             if (header.len < 14 + 20 + 20) {
//                 continue;
//             }

//             struct iphdr *ip = (struct iphdr *)(packet + 14);
//             struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + (ip->ihl * 4));
            
//             uint32_t ack_num = ntohl(tcp->ack_seq);
//             uint32_t expected_ack = args->sent_seq + 1;
            
//             printf("Received: src=%s:%d dst=%s:%d seq=%u ack=%u flags=[%s%s%s%s]\n",
//                    inet_ntoa(*(struct in_addr*)&ip->saddr), ntohs(tcp->source),
//                    inet_ntoa(*(struct in_addr*)&ip->daddr), ntohs(tcp->dest),
//                    ntohl(tcp->seq), ack_num,
//                    tcp->syn ? "SYN " : "",
//                    tcp->ack ? "ACK " : "",
//                    tcp->rst ? "RST " : "",
//                    tcp->fin ? "FIN " : "");

//             if (ntohs(tcp->source) == args->port && 
//                 ntohs(tcp->dest) == args->src_port) {
                
//                 pthread_mutex_lock(&args->config->mutex);
                
//                 if (tcp->syn && tcp->ack) {
//                     if (ack_num == expected_ack || ack_num == 0) {                         args->state = STATE_OPEN;
//                         printf("Port %d: OPEN (SYN-ACK received)\n", args->port);
//                     } else {
//                         printf("Port %d: SYN-ACK with unexpected ack=%u (expected %u)\n", 
//                                args->port, ack_num, expected_ack);
//                         args->state = STATE_OPEN;
//                     }
//                 } else if (tcp->rst) {
//                     args->state = STATE_CLOSED;
//                     printf("Port %d: CLOSED (RST received)\n", args->port);
//                 } else {
//                     printf("Port %d: Unexpected response flags\n", args->port);
//                 }
                
//                 pthread_cond_signal(&args->config->cond);
//                 pthread_mutex_unlock(&args->config->mutex);
//                 break;
//             }
//         }

//         usleep(1000);
//     }

//     pcap_freecode(&fp);
//     pcap_close(handle);
//     free((void*)interface);
//     return NULL;
// }


void *capture_responses_debug(void *arg) {
    capture_thread_args *args = (capture_thread_args *)arg;
    const char *interface = find_interface_for_target(args->config->ip);
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter[512];
    struct bpf_program fp;
    struct timeval start, now;
    const double timeout_seconds = 5.0;
    int packet_count = 0;
    
    printf("DEBUG: starting capture on interface %s for port %d\n", interface, args->port);
    printf("DEBUG: Looking for responses from %s to our port %d\n", args->config->ip, args->src_port);
    
    pcap_t *handle = pcap_open_live(interface, 65536, 1, 1, errbuf);
    if (!handle) {
        fprintf(stderr, "Could not open %s: %s\n", interface, errbuf);
        free((void*)interface);
        free(args);
        return NULL;
    }

    const char *src_ip = get_interface_ip(args->config->ip);
    snprintf(filter, sizeof(filter), "tcp");
    // snprintf(filter, sizeof(filter), 
        //  "tcp and src host %s and src port %d and dst host %s and dst port %d",
        //  args->config->ip, args->port, src_ip, args->src_port);
    
    if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Filter error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        free((void*)interface);
        free(args);
        return NULL;
    }

    printf("DEBUG: Using targeted filter: %s\n", filter); 
    printf("DEBUG: Expected source IP: %s, source port: %d\n", src_ip, args->src_port);
    printf("DEBUG: Target IP: %s, target port: %d\n", args->config->ip, args->port);

    if (pcap_setnonblock(handle, 1, errbuf) == -1) {
        fprintf(stderr, "Could not set non-blocking mode: %s\n", errbuf);
    }

    gettimeofday(&start, NULL);

    while (args->state == STATE_WAITING && packet_count < 100) {
        struct pcap_pkthdr header;
        const u_char *packet = pcap_next(handle, &header);
        
        gettimeofday(&now, NULL);
        double elapsed = (now.tv_sec - start.tv_sec) + 
                        (now.tv_usec - start.tv_usec) / 1000000.0;
        
        if (elapsed > timeout_seconds) {
            printf("DEBUG: Timeout reached after %.1fs, captured %d packets\n", elapsed, packet_count);
            pthread_mutex_lock(&args->config->mutex);
            if (args->state == STATE_WAITING) {
                args->state = STATE_FILTERED;
                printf("Port %d: FILTERED (timeout after %.1fs)\n", args->port, elapsed);
                pthread_cond_signal(&args->config->cond);
            }
            pthread_mutex_unlock(&args->config->mutex);
            break;
        }
        
        if (packet) {
            packet_count++;
            printf("DEBUG: Captured packet %d, length: %d bytes\n", packet_count, header.len);
            if (header.len < 14 + 20 + 20) {
                continue;
            }

            struct iphdr *ip = (struct iphdr *)(packet + 14);
            struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + (ip->ihl * 4));
            
            char src_ip_str[INET_ADDRSTRLEN];
            char dst_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip->saddr, src_ip_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &ip->daddr, dst_ip_str, INET_ADDRSTRLEN);
            
            printf("DEBUG[%d]: %s:%d -> %s:%d flags=[%s%s%s%s] seq=%u ack=%u\n",
                   packet_count, src_ip_str, ntohs(tcp->source),
                   dst_ip_str, ntohs(tcp->dest),
                   tcp->syn ? "SYN " : "",
                   tcp->ack ? "ACK " : "",
                   tcp->rst ? "RST " : "",
                   tcp->fin ? "FIN " : "",
                   ntohl(tcp->seq), ntohl(tcp->ack_seq));

            //TODO: the DEBUG above show that we are receiving a response to our scan SYN-ACK but it is not seting the port as open here ??
            pthread_mutex_lock(&args->config->mutex);
            if (tcp->syn && tcp->ack) {
                args->state = STATE_OPEN;
                printf("Port %d: OPEN (SYN-ACK received)\n", args->port);
                pthread_cond_signal(&args->config->cond);
                pthread_mutex_unlock(&args->config->mutex);
                break;
            } else if (tcp->rst) {
                args->state = STATE_CLOSED;
                printf("Port %d: CLOSED (RST received)\n", args->port);
                pthread_cond_signal(&args->config->cond);
                pthread_mutex_unlock(&args->config->mutex);
                break;
            }
            pthread_mutex_unlock(&args->config->mutex);
        }

        usleep(1000);
    }

    printf("DEBUG: Capture finished, total packets: %d\n", packet_count);
    pcap_freecode(&fp);
    pcap_close(handle);
    free((void*)interface);
    return NULL;
}