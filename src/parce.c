#include "../include/ft_nmap.h"

// Parse port ranges like "80,443,1000-2000" , and default scan to SYN-SCAn
void parse_ports() {
    if (!g_config.ports) {
        // Default ports 1-1024
        for (int i = 1; i <= 1024; i++) {
            add_port(i, SCAN_SYN); 
        }
        return;
    }

    // Parse the ports string
    char *token = strtok(g_config.ports, ",");
    while (token) {
        char *dash = strchr(token, '-');
        if (dash) {
            int start = atoi(token);
            int end = atoi(dash + 1);
            for (int p = start; p <= end; p++) {
                add_port(p, SCAN_SYN); 
            }
        } else {
            add_port(atoi(token), SCAN_SYN); 
        }
        token = strtok(NULL, ",");
    }
}

// Parse scan types like "SYN,NULL,FIN"
void parse_scan_types() {
    if (!g_config.scans) {
        t_port *current = g_config.port_list;
        while (current) {
            current->scan_type = SCAN_SYN;
            current = current->next;
        }
        return;
    }

    // Parse the scan types string
    char *token = strtok(g_config.scans, ",");
    while (token) {
        scan_type_t scan_type;
        if (strcmp(token, "S") == 0) {
            scan_type = SCAN_SYN;
        } else if (strcmp(token, "N") == 0) {
            scan_type = SCAN_NULL;
        } else if (strcmp(token, "F") == 0) {
            scan_type = SCAN_FIN;
        } else if (strcmp(token, "X") == 0) {
            scan_type = SCAN_XMAS;
        } else if (strcmp(token, "A") == 0) {
            scan_type = SCAN_ACK;
        } else if (strcmp(token, "U") == 0) {
            scan_type = SCAN_UDP;
        } else {
            fprintf(stderr, "Unknown scan type: %s\n", token);
            exit(EXIT_FAILURE);
        }

        // Apply the scan type to all ports
        t_port *current = g_config.port_list;
        while (current) {
            current->scan_type = scan_type;
            current = current->next;
        }

        token = strtok(NULL, ",");
    }
}
