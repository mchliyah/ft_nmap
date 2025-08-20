#include "../include/ft_nmap.h"


void print_help(void) {

    printf("Usage: ./ft_nmap [OPTIONS]\n");
    printf("Options:\n");
    printf("  --help\t\t\tShow this help message\n");
    printf("  --ports [LIST/RANGE]\t\tPorts to scan (e.g. 22,80,443 or 20-80)\n");
    printf("  --ip [IP]\t\t\tIP address to scan\n");
    printf("  --file [filename]\t\tRead IPs from file\n");
    printf("  --speedup [N]\t\t\tNumber of threads (max 250)\n");
    printf("  --scan [TYPES]\t\tScan types: SYN, NULL, FIN, XMAS, ACK, UDP\n");
    exit(0);
}

void print_debug(void) {
    // Print configuration (for now)
    printf("Scan Configurations:\n");
    if (g_config.ip) printf("Target IP: %s\n", g_config.ip);
    if (g_config.file) printf("Input File: %s\n", g_config.file);
    printf("Ports: %s\n", g_config.ports ? g_config.ports : "1-1024 (default)");
    printf("Scan types: %s\n", g_config.scans ? g_config.scans : "All");
    printf("Speedup (threads): %d\n", g_config.speedup);
}


// void print_complete_scan(t_config *config) {
// }
// void print_scan_result(t_config *config, int port, port_state_t state, scan_type_t scan_type) {
// }
