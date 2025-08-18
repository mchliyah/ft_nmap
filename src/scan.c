#include "../include/ft_nmap.h"

void run_scan(t_config *config) {
    parse_ports(config);
    parse_scan_types(config);

    // Initialize scan state
    config->scan_complete = 0;
    config->scaner_on = 0;
    config->scan_start_time = time(NULL);

    // Validate and clamp thread count
    config->speedup = (config->speedup < 1) ? 1 : 
                     (config->speedup > 250) ? 250 : config->speedup;

    printf("Starting scan with %d threads on %d ports (30 second timeout)...\n", 
          config->speedup, config->port_count);

    // Start ONE global listener thread
    pthread_t global_listener;
    if (pthread_create(&global_listener, NULL, start_listner, config) != 0) {
        perror("Failed to create global listener thread");
        exit(EXIT_FAILURE);
    }

    // Give listener time to initialize
    usleep(50000);

    pthread_t threads[config->speedup];
    scan_thread_data thread_data[config->speedup];

    for (int i = 0 ; i < config->speedup; i++){
        memset(&thread_data, 0, sizeof(thread_data));
    }
    
    // Calculate ports per thread
    int ports_per_thread = config->port_count / config->speedup;
    int remaining_ports = config->port_count % config->speedup;
    int current_port = 0;

    // Create scanner threads (without their own listeners)
    for (int i = 0; i < config->speedup; i++) {
        printf("port : %d  ; end port : %d \n", current_port, remaining_ports);
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

    // Wait for all scanner threads to complete
    for (int i = 0; i < config->speedup; i++) {
        pthread_join(threads[i], NULL);
    }

    // Wait additional time for responses if no open port found yet
    if (!config->scan_complete) {
        printf("All packets sent, waiting for responses...\n");
        int additional_wait = 5; // Wait 5 more seconds for responses
        time_t wait_start = time(NULL);
        
        while (!config->scan_complete && (time(NULL) - wait_start) < additional_wait) {
            if ((time(NULL) - config->scan_start_time) > 30) {
                printf("Overall timeout reached\n");
                break;
            }
            usleep(100000); // Check every 100ms
        }
    }

    // Stop the global listener
    config->scaner_on = 0;
    pthread_join(global_listener, NULL);

    // Final status
    time_t elapsed = time(NULL) - config->scan_start_time;
    if (config->scan_complete) {
        printf("Scan completed - open port found in %ld seconds\n", elapsed);
    } else if (elapsed >= 30) {
        printf("Scan completed - timeout reached after %ld seconds\n", elapsed);
    } else {
        printf("Scan completed - no open ports found in %ld seconds\n", elapsed);
    }

    printf("Scan completed!\n");
}