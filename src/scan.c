#include "../include/ft_nmap.h"

void finalize_udp_scan() {
    pthread_mutex_lock(&g_config.port_mutex);
    t_port *current = g_config.port_list;
    // PRINT_DEBUG();
    while (current) {
        // For UDP scans, if port hasn't been marked for printing and has UDP protocol
        if (!current->to_print && current->tcp_udp && strcmp(current->tcp_udp, "udp") == 0) {
            // No response received - mark as open|filtered
            current->state = STATE_OPEN_FILTERED;
            // PRINT_DEBUG();
            // current->to_print = true;
            
            if (g_config.reason) {
                current->reason = strdup("no-response");
            }
            
            V_PRINT(2, "UDP port %d marked as open|filtered (no response)\n", current->port);
        }
        current = current->next;
    }
    
    pthread_mutex_unlock(&g_config.port_mutex);
}

void start_thread_listner(pthread_t *global_listener) {

    time_t now = time(NULL);
    V_PRINT(1, "Initiating Parallel DNS resolution of %d host\n", g_config.ip_count);
    if (pthread_create(global_listener, NULL, start_listner, NULL) != 0) {
        perror("Failed to create global listener thread");
        exit(EXIT_FAILURE);
    }
    V_PRINT(1, "Parallel DNS resolution completed in %.2f seconds\n", difftime(time(NULL), now));
}


void start_sender_threads(int sock, pthread_t *threads, scan_thread_data *thread_data) {

    int ports_per_thread = g_config.port_count / g_config.speedup;
    int remaining_ports = g_config.port_count % g_config.speedup;
    int start_range = 0;
    t_port *current = g_config.port_list;

    V_PRINT(1, "Initializing %s scan at %s\n", get_scan_type_name(), get_current_time_short());
    V_PRINT(1, "Scanning %s [%d ports]\n", g_config.ip, g_config.port_count);
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
    pthread_cancel(global_listener);
    pthread_join(global_listener, NULL);

}

void timeout_scan_result( pthread_t global_listener) {

        if (!g_config.scan_complete) {
        int additional_wait = 3;
        time_t wait_start = time(NULL);
        while (!g_config.scan_complete && (time(NULL) - wait_start) < additional_wait) {
            if ((time(NULL) - g_config.scan_start_time) > g_config.timeout) {
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

    time_t scan_start = time(NULL);
    start_thread_listner(&global_listener);
    usleep(100000);
    int sock = set_socket();
    start_sender_threads(sock, threads, thread_data);
    for (int i = 0; i < g_config.speedup; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // Finalize UDP scan results - mark unresponsive ports as open|filtered
    if (g_config.scan_types.udp) {
        finalize_udp_scan();
    }
    
    V_PRINT(1, "Completed %s Scan at %s, %.2fs elapsed (%d total ports)\n",
           get_scan_type_name(), ctime(&scan_start), difftime(time(NULL), scan_start), g_config.port_count);
    close(sock);
    timeout_scan_result(global_listener);

}