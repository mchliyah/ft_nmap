#include "../include/ft_nmap.h"


void print_help(void) {

    printf("Usage: ./ft_nmap [OPTIONS]\n");
    printf("Options:\n");
    printf("  --help\t\t\tShow this help message\n");
    printf("  --ports [LIST/RANGE]\t\tPorts to scan (e.g. 22,80,443 or 20-80)\n");
    printf("  --ip [IP]\t\t\tIP address to scan\n");
    printf("  --file [filename]\t\tRead IPs from file\n");
    printf("  --speedup [N]\t\t\tNumber of threads (max 250)\n");
    printf("  --scan [TYPES]\t\tScan types: SYN (S), NULL (N), FIN (F), XMAS (X), ACK (A), UDP (U)\n");
    printf("  --reason, -r\t\t\tDisplay reason a port is in a particular state\n");
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
    if (g_config.reason) {
        printf("PORT       STATE        SERVICE      REASON\n");
    } else {
        printf("PORT       STATE        SERVICE\n");
    }
    t_port *current = g_config.port_list;
    

    while (current) {
        if (current->to_print) {
            if (g_config.reason) {
                printf("%d/%-4s  %-12s %-12s %s\n", current->port, current->tcp_udp, 
                       port_state_to_string(current->state), 
                       current->service ? current->service : "unknown",
                       current->reason ? current->reason : "no-response");
            } else {
                printf("%d/%-4s  %-12s %s\n", current->port, current->tcp_udp, 
                       port_state_to_string(current->state), 
                       current->service ? current->service : "unknown");
            }
        }
        current = current->next;
    }
}