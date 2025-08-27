#include "../include/ft_nmap.h"

void start_thread_listner(pthread_t *global_listener) {
    // This function will handle incoming packets and update the scan results
    // It should be implemented to listen for responses from the target IPs
    // puts("Starting global listener thread...");
    if (pthread_create(global_listener, NULL, start_listner, NULL) != 0) {
        perror("Failed to create global listener thread");
        exit(EXIT_FAILURE);
    }
    // puts("Global listener thread started successfully.");
}


void start_sender_threads(int sock, pthread_t *threads, scan_thread_data *thread_data) {

    int ports_per_thread = g_config.port_count / g_config.speedup;
    int remaining_ports = g_config.port_count % g_config.speedup;
    int start_range = 0;
    t_port *current = g_config.port_list;

    // int thread_created = 0;

    for (int i = 0; i < g_config.speedup; i++) {
        thread_data[i] = (scan_thread_data){
            .sock = sock,
            .thread_id = i,
            .current = current,
            .start_range = start_range,
            .end_range = start_range + ports_per_thread + (i < remaining_ports ? 1 : 0)
        };
        if (pthread_create(&threads[i], NULL, scan_thread, &thread_data[i]) != 0) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
        // thread_created++;
        start_range = thread_data[i].end_range;
        // Move current pointer to the start of the next thread's range
        while (current && current->port < start_range) {
            current = current->next;
        }
    }
}


void cleanup(pthread_t *threads, pthread_t global_listener) {
    (void)threads;
    // Cleanup resources after scan completion
    // for (int i = 0; i < g_config.speedup; i++) {
    //     pthread_cancel(threads[i]);
    //     pthread_join(threads[i], NULL);
    // }
    
    pthread_cancel(global_listener);
    pthread_join(global_listener, NULL);

    // Free allocated memory for ports and scan types
    // for (int i = 0; i < g_config.scan_type_count; i++) {
    //     if (g_config.scan_types[i]) {
    //         free(g_config.scan_types[i]);
    //     }
    // }
    // if (g_config.scan_types) {
    //     free(g_config.scan_types);
    // }
}

void timeout_scan_result( pthread_t global_listener) {

        if (!g_config.scan_complete) {
        int additional_wait = 3;
        time_t wait_start = time(NULL);
        while (!g_config.scan_complete && (time(NULL) - wait_start) < additional_wait) {
            if ((time(NULL) - g_config.scan_start_time) > 30) {
                printf("Overall timeout reached\n");
                break;
            }
            usleep(100000);
        }
    }

    time_t elapsed = time(NULL) - g_config.scan_start_time;
    if (g_config.scan_complete) {
        // printf("Scan completed - open port found in %ld seconds\n", elapsed);
    } else if (elapsed >= 30) {
        // printf("Scan completed - timeout reached after %ld seconds\n", elapsed);
        pthread_cancel(global_listener);
        // pthread_join(global_listener, NULL);
        // printf("Scan listener thread cancelled due to timeout.\n");
        // g_config.scan_complete = 1; // Mark scan as complete to exit threads
        // pthread_cond_broadcast(&g_config.cond); // Notify all threads to exit
        // cleanup(threads, global_listener, thread_data);
        return;
    }
}

int set_socket(){

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    //set socket to send all packets
    int on = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    return sock;
}

void run_scan() {

    // init threads 
    pthread_t global_listener;
    pthread_t threads[g_config.speedup];
    scan_thread_data thread_data[g_config.speedup];


    //start the thread listner 
    start_thread_listner(&global_listener);
    usleep(100000);
    // threads chunk sender
    int sock = set_socket();
    start_sender_threads(sock, threads, thread_data);
    // printf("Waiting for scanning threads to complete...\n");
    for (int i = 0; i < g_config.speedup; i++) {
        pthread_join(threads[i], NULL);
    }

    close(sock);
    // printf("All scanning threads completed\n");

    // Handle timeout and results
    timeout_scan_result(global_listener);
    // cleanup(threads, global_listener);

}