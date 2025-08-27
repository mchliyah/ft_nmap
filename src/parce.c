#include "../include/ft_nmap.h"

// Parse port ranges like "80,443,1000-2000" , and default scan to SYN-SCAn
void parse_ports() {
    // if (!g_config.ports && (!g_config.scan_type_count || g_config.scan_types.syn == SCAN_SYN))
    if (!g_config.ports) { // i do not remember why i set the previes conditions 
        for (int i = 1; i <= 1024; i++) add_port(i, STATE_FILTERED);
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
                add_port(p, STATE_FILTERED);
            }
        } else {
            add_port(atoi(token), STATE_FILTERED);
        }
        token = strtok(NULL, ",");
    }
}

void set_scan_type(t_port *port, scan_type scan_type)
{
    switch (scan_type) {
        case SCAN_SYN:
            port->state = STATE_FILTERED;
            break;
        case SCAN_NULL:
            port->state = STATE_OPEN;
            break;
        case SCAN_FIN:
            port->state = STATE_OPEN;
            break;  
        case SCAN_XMAS:
            port->state = STATE_OPEN;
            break;
        case SCAN_ACK:
            port->state = STATE_FILTERED;
            break;
        case SCAN_UDP:
            port->state = STATE_CLOSED;
            break;
    }

}
// Parse scan types like "SYN,NULL,FIN" or "S,N,F"
void parse_scan_types() {
    if (!g_config.scans)
    {
        g_config.scan_types.syn = SCAN_SYN;
        g_config.scan_type_count = 1;
        return;
    }

    char *token = strtok(g_config.scans, ",");
    while (token)
    {
        // Support both single letters and full names
        if (strcmp(token, "S") == 0 || strcmp(token, "SYN") == 0) {
            g_config.scan_types.syn = SCAN_SYN;
        } else if (strcmp(token, "N") == 0 || strcmp(token, "NULL") == 0) {
            g_config.scan_types.null = SCAN_NULL;
        } else if (strcmp(token, "F") == 0 || strcmp(token, "FIN") == 0) {
            g_config.scan_types.fin = SCAN_FIN;
        } else if (strcmp(token, "X") == 0 || strcmp(token, "XMAS") == 0) {
            g_config.scan_types.xmas = SCAN_XMAS;
        } else if (strcmp(token, "A") == 0 || strcmp(token, "ACK") == 0) {
            g_config.scan_types.ack = SCAN_ACK;
        } else if (strcmp(token, "U") == 0 || strcmp(token, "UDP") == 0) {
            g_config.scan_types.udp = SCAN_UDP;
        } else {
            fprintf(stderr, "Unknown scan type: %s\n", token);
            fprintf(stderr, "Supported scan types: SYN (S), NULL (N), FIN (F), XMAS (X), ACK (A), UDP (U)\n");
            exit(EXIT_FAILURE);
        }
        g_config.scan_type_count++;
        
        token = strtok(NULL, ",");
    }
}

