#include "../include/ft_nmap.h"

t_config g_config = INIT_CONFIG();

void init_scan() {
    
    printf("Starting Ft_nmap at %s \n", get_current_time());
    if (g_config.ip_count > 0) {
        V_PRINT(1, "Scanning %d IP address(es).\n", g_config.ip_count);
    } else if (g_config.file) {
        V_PRINT(1, "Scanning IPs from file: %s\n", g_config.file);
    }
    if (g_config.ports) V_PRINT(1, "Ports: %s\n", g_config.ports);
    if (g_config.scans) V_PRINT(1, "Scan types: %s\n", g_config.scans);

    V_PRINT(2, "Threads: %d\n", g_config.speedup);
    g_config.speedup = (g_config.speedup < 1) ? 1 : 
    (g_config.speedup > 250) ? 250 : g_config.speedup;

    srand(time(NULL));
    g_config.scan_start_time = time(NULL);
    g_config.src_ip = get_interface_ip(g_config.ip);
}

const char* get_current_time() {
    time_t now = time(NULL);
    return ctime(&now);
}

double get_elapsed_time() {
    return difftime(time(NULL), g_config.scan_start_time);
}

int main(int argc, char **argv) {
    //parse
    parse_args(argc, argv);
    parse_scan_types();
    parse_ports();
    //init & scan
    init_scan();
    run_scan();
    //done and print
    print_scan_result();
    print_verbose_statistics();
    //cleanup 
    // cleanup_ports();
    free_ip_list(g_config.ips);
    return 0;
}