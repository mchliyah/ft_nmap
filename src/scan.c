#include "../include/ft_nmap.h"


void run_scan(t_config *config) {
    parse_ports(config);
    parse_scan_types(config);

    // Validate and clamp thread count
    config->speedup = (config->speedup < 1) ? 1 : 
                     (config->speedup > 250) ? 250 : config->speedup;

    pthread_t threads[config->speedup];
    scan_thread_data thread_data[config->speedup];
    
    // Calculate ports per thread
    int ports_per_thread = config->port_count / config->speedup;
    int remaining_ports = config->port_count % config->speedup;
    int current_port = 0;

    printf("Starting scan with %d threads on %d ports...\n", 
          config->speedup, config->port_count);
    for (int i = 0; i < config->speedup; i++) {
        thread_data[i] = (scan_thread_data){
            .thread_id = i,
            .config = config,
            .start_port = current_port,
            .end_port = current_port + ports_per_thread + (i < remaining_ports ? 1 : 0)
        };
        
        if (pthread_create(&threads[i], NULL, scan_thread, &thread_data[i]) != 0) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
        
        current_port = thread_data[i].end_port;
    }
    for (int i = 0; i < config->speedup; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("Scan completed!\n");
}