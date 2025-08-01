
#include "../include/ft_nmap.h"
// Thread worker function

void *scan_thread(void *arg) {
    scan_thread_data *data = (scan_thread_data *)arg;
    t_config *config = data->config;
    
    printf("Thread %d: Scanning ports %d-%d\n", 
          data->thread_id, data->start_port, data->end_port - 1);

    for (int port_idx = data->start_port; port_idx < data->end_port; port_idx++) {
        int port = config->port_list[port_idx];
        struct servent *service = getservbyport(htons(port), "tcp");
        
        for (int scan_idx = 0; scan_idx < config->scan_type_count; scan_idx++) {
            const char *scan_type = config->scan_types[scan_idx];
            
            printf("[Thread %d] Port %d (%s): %s scan - ",
                  data->thread_id, port,
                  service ? service->s_name : "unknown",
                  scan_type);

            // Common scan preparation
            struct sockaddr_in target = {
                .sin_family = AF_INET,
                .sin_port = htons(port)
            };
            inet_pton(AF_INET, config->ip, &target.sin_addr);

            //different scan types
            if (strcmp(scan_type, "SYN") == 0) {
                // SYN Scan implementation
                int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
                if (sock < 0) {
                    perror("socket(SYN)");
                    continue;
                }
                
                // TODO: socket options and build TCP SYN packet
                // (Implementation depends on packet crafting)
                
                close(sock);
                printf("SYN sent\n");
            }
            else if (strcmp(scan_type, "UDP") == 0) {
                // UDP Scan implementation
                int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                if (sock < 0) {
                    perror("socket(UDP)");
                    continue;
                }
                
                // UDP scan logic
                if (connect(sock, (struct sockaddr *)&target, sizeof(target)) == 0) {
                    printf("UDP open\n");
                } else {
                    printf("UDP %s\n", errno == ECONNREFUSED ? "closed" : "filtered");
                }
                close(sock);
            }
            // TODO: other scan types (NULL, FIN, XMAS, ACK)
            else {
                printf("Scan type not implemented\n");
            }
        }
    }
    return NULL;
}
