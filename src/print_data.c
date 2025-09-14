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


const char *port_state_to_string(int state) {
    switch (state) {
        case STATE_OPEN:   return "open";
        case STATE_CLOSED: return "closed";
        case STATE_FILTERED:return "filtered";
        case STATE_OPEN_FILTERED: return "open|filtered";
        default:          return NULL;
    }
}

void print_port(t_port *current) {
    char port_field[16];
    snprintf(port_field, sizeof(port_field), "%d/%s", current->port, current->tcp_udp);

    if (g_config.reason || g_config.verbose > 2 ) {
        /* Columns: PORT (9), STATE (12), SERVICE (12), REASON */
        printf("%-9s %-12s %-12s %s\n",
               port_field,
               port_state_to_string(current->state),
               current->service ? current->service : "unknown",
               current->reason ? current->reason : "no-response");
    } else {
        /* Columns: PORT (9), STATE (12), SERVICE (12) */
        printf("%-9s %-12s %-12s\n",
               port_field,
               port_state_to_string(current->state),
               current->service ? current->service : "unknown");
    }
}

bool there_is_ports(t_ips *ips){
    t_port *port = ips->port_list;
    while (port){
        if (port->to_print)
            return true;
        port = port->next;
    }
    printf("nothing to print \n");
    return false;
}

void print_scan_result(void) {

    V_PRINT(1, "Completed %s Scan at %s, %.2fs elapsed (%d total ports)\n",
           get_scan_type_name(), ctime(&g_config.scan_start_time), difftime(time(NULL), g_config.scan_start_time), g_config.port_count);
    t_ips *ips = g_config.ips;
    while (ips) {
        if (ips->is_up){
            printf("\nFt_nmap scan report for %s (%s)\n", ips->resolve_hostname? ips->resolve_hostname: "", ips->ip);
            if (!g_config.is_port_default || there_is_ports(ips)){
                if (g_config.reason || g_config.verbose > 2) {
                    /* Match widths used in print_port(): PORT(9) STATE(12) SERVICE(12) REASON */
                    printf("%-9s %-12s %-12s %s\n", "PORT", "STATE", "SERVICE", "REASON");
                } else {
                    printf("%-9s %-12s %-12s\n", "PORT", "STATE", "SERVICE");
                }
                t_port *current = ips->port_list;
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
        }else
            printf("host %s is down.\n", ips->ip);
        ips = ips->next;

    }
    printf("\nFt_nmap done: %d IP address (%d hosts up) scaned in %.2f seconds.\n", g_config.ip_count, g_config.up_hosts, difftime(time(NULL), g_config.scan_start_time));
    

}