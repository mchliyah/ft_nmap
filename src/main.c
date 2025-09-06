#include "../include/ft_nmap.h"

// Define g_config in main.c
t_config g_config = INIT_CONFIG();

void init_scan() {
    g_config.speedup = (g_config.speedup < 1) ? 1 : 
    (g_config.speedup > 250) ? 250 : g_config.speedup;

    srand(time(NULL));
    g_config.scan_start_time = time(NULL);
    g_config.src_ip = get_interface_ip(g_config.ip);
    printf("Nmap scan report for %s\n\n", g_config.ip);
}

void scan_single_ip(const char* target_ip) {
    g_config.ip = (char*)target_ip;
    g_config.src_ip = get_interface_ip(target_ip);
    g_config.scan_start_time = time(NULL);
    g_config.scan_complete = 0;
    run_scan();
}

void handle_multi_ip_scan() {
    for (int i = 0; i < g_config.ip_count; i++) {
        scan_single_ip(g_config.ip_list[i]);
        if (i < g_config.ip_count - 1) {
            printf("\n");
        }
    }
    for (int i = 0; i < g_config.ip_count; i++) {
        free(g_config.ip_list[i]);
    }
    free(g_config.ip_list);
}

void handle_file_scan() {
    int ip_count = 0;
    char** ips = read_ips_from_file(g_config.file, &ip_count);
    
    if (!ips || ip_count == 0) {
        fprintf(stderr, "Error: Failed to read IP addresses from file '%s'\n", g_config.file);
        exit(1);
    }
    
    printf("Starting scan of %d IP address(es) from file '%s'\n", ip_count, g_config.file);
    
    for (int i = 0; i < ip_count; i++) {
        scan_single_ip(ips[i]);
        if (i < ip_count - 1) {
            printf("\n");
        }
    }
    
    free_ip_array(ips, ip_count);
}

void handle_single_ip_scan() {
    init_scan();
    run_scan();
}

void initialize_config() {
    g_config.speedup = (g_config.speedup < 1) ? 1 : 
                      (g_config.speedup > 250) ? 250 : g_config.speedup;
    srand(time(NULL));
}

void cleanup_ports() {
    t_port *current = g_config.port_list;
    while (current) {
        t_port *next = current->next;
        free(current);
        current = next;
    }
}

const char* get_current_time() {
    time_t now = time(NULL);
    g_config.scan_start_time = now;
    return ctime(&now);
}

double get_elapsed_time() {
    return difftime(time(NULL), g_config.scan_start_time);
}

int main(int argc, char **argv) {
    parse_args(argc, argv); // args to use 
    parse_scan_types(); // scan types first to make default ports dependence
    parse_ports(); // port target using default scan types or target 
    V_PRINT(1, "Starting ft_nmap at %s\n", get_current_time());
    V_PRINT(1, "Target: %s\n", g_config.ip);
    if (g_config.ports) V_PRINT(1, "Ports: %s\n", g_config.ports);
    if (g_config.scans) V_PRINT(1, "Scan types: %s\n", g_config.scans);
    initialize_config();

    V_PRINT(2, "Threads: %d\n", g_config.speedup);
    if (g_config.ip_list && g_config.ip_count > 0) {
        handle_multi_ip_scan();
    } else if (g_config.file) {
        handle_file_scan();
    } else if (g_config.ip) {
        handle_single_ip_scan();
    } else {
        fprintf(stderr, "Error: No IP address or file specified\n");
        return 1;
    }
    print_scan_result();
    V_PRINT(1, "Scan completed in %.2f seconds\n", get_elapsed_time());
    cleanup_ports();
    return 0;
}
