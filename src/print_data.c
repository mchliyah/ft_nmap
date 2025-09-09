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
        case STATE_OPEN:   return "open";
        case STATE_CLOSED: return "closed";
        case STATE_FILTERED:return "filtred";
        case STATE_OPEN_FILTERED: return "open|filtred";
        default:          return NULL;
    }
}

void print_port(t_port *current) {
    if (g_config.reason || g_config.verbose > 2 ) {
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

void print_scan_result(void) {
     V_PRINT(1, "Completed %s Scan at %s, %.2fs elapsed (%d total ports)\n",
           get_scan_type_name(), ctime(&g_config.scan_start_time), difftime(time(NULL), g_config.scan_start_time), g_config.port_count);
    if (g_config.reason || g_config.verbose > 2) {
        printf("PORT       STATE        SERVICE      REASON\n");
    } else {
        printf("PORT       STATE        SERVICE\n");
    }
    t_port *current = g_config.port_list;
    

    if (!g_config.is_port_default){
        while (current) {
            print_port(current);
            current = current->next;
        }
    }
    else if (g_config.is_port_default){
        while (current) {
            if (current->to_print) {
                print_port(current);
            }
            current = current->next;
        }
    }
}