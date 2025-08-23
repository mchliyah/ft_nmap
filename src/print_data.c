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


const char *port_state_to_string(int state) {
    switch (state) {
        case STATE_OPEN:   return "OPEN";
        case STATE_CLOSED: return "CLOSED";
        case STATE_FILTERED:return "FILTERED";
        default:          return NULL;
    }
}

void print_scan_result(void) {
    // Print the results of the scan
    printf("Scan Results:\n");
    t_port *current = g_config.port_list;
    //no scan type specified
    if (g_config.scans) {
        while (current) {
            const char *state_str = port_state_to_string(current->state);
            if (state_str) {
                printf("Port %d: %s\n", current->port, state_str);
            }
            current = current->next;
        }
    }
    // scan type specified 
    else if (!g_config.scans) {
        while (current) {
            if (current->state != STATE_CLOSED) {
                printf("Port %d: %s\n", current->port, port_state_to_string(current->state));
            }
            current = current->next;
        }
    }
}