#include "../include/ft_nmap.h"

void finalize_udp_scan() {
    pthread_mutex_lock(&g_config.port_mutex);
    t_port *current = g_config.port_list;
    
    while (current) {
        // For UDP scans, if port hasn't been marked for printing and has UDP protocol
        if (!current->to_print && current->tcp_udp && strcmp(current->tcp_udp, "udp") == 0) {
            // No response received - mark as open|filtered
            current->state = STATE_OPEN_FILTERED;
            current->to_print = true;
            
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


void start_sender_threads(int sock, pthread_t *threads, t_ips *current_ips, scan_thread_data *thread_data) {

    int ports_per_thread = g_config.port_count / g_config.speedup;
    int remaining_ports = g_config.port_count % g_config.speedup;
    int start_range = 0;

    t_port *current = current_ips->port_list;


    V_PRINT(1, "Initializing %s scan at %s\n", get_scan_type_name(), get_current_time_short());
    V_PRINT(1, "Scanning %s [%d ports]\n", current_ips->ip, g_config.port_count);
    for (int i = 0; i < g_config.speedup; i++) {
        thread_data[i] = (scan_thread_data){
            .sock = sock,
            .thread_id = i,
            .ips = current_ips,
            .current = current,
            .start_range = start_range,
            .end_range = start_range + ports_per_thread + (i < remaining_ports ? 1 : 0)
        };
        if (pthread_create(&threads[i], NULL, scan_thread, &thread_data[i]) != 0) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
        start_range = thread_data[i].end_range;
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
        int additional_wait = g_config.timeout;
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

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
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

bool is_a_host_up(void){
    t_ips *current_ips = g_config.ips;
    while (current_ips){
        if (current_ips->is_up)
            g_config.up_hosts++;
        current_ips = current_ips->next;
    }
    return g_config.up_hosts > 0;
}

void run_scan() {
    
    int sock = set_socket();
    pthread_t global_listener;
    t_ips *current_ips = g_config.ips;
    bool hosts_up = is_a_host_up();

    if (hosts_up){
        start_thread_listner(&global_listener);
        usleep(100000);
    }

    while(current_ips) {

        V_PRINT(1, "Scanning %s\n", current_ips->ip);
        if (current_ips){

            pthread_t threads[g_config.speedup];
            scan_thread_data thread_data[g_config.speedup];
            
            start_sender_threads(sock, threads, current_ips, thread_data);
            
            for (int i = 0; i < g_config.speedup; i++) {
                pthread_join(threads[i], NULL);
            }
        }
        
        V_PRINT(1, "Completed %s Scan for %s at %s, %.2fs elapsed (%d total ports)\n",
        get_scan_type_name(), current_ips->ip, ctime(&g_config.scan_start_time), 
        difftime(time(NULL), g_config.scan_start_time), g_config.port_count);
        current_ips = current_ips->next;
    }
    if (hosts_up)
        timeout_scan_result(global_listener);
    close(sock);
}