#include "../include/ft_nmap.h"

// Parse port ranges like "80,443,1000-2000"
void parse_ports(t_config *config) {
    if (!config->ports) {
        // Default ports 1-1024
        config->port_count = 1024;
        config->port_list = malloc(config->port_count * sizeof(int));
        for (int i = 0; i < config->port_count; i++) {
            config->port_list[i] = i + 1;
        }
        return;
    }

    // Count ports first
    config->port_count = 0;
    char *token = strtok(config->ports, ",");
    while (token) {
        char *dash = strchr(token, '-');
        if (dash) {
            int start = atoi(token);
            int end = atoi(dash + 1);
            config->port_count += (end - start + 1);
        } else {
            config->port_count++;
        }
        token = strtok(NULL, ",");

        // TODO: check that the ports are numbers (ERROR 80,str,443)
    }

    // Allocate and fill port list
    config->port_list = malloc(config->port_count * sizeof(int));
    strcpy(config->ports, strdup(config->ports)); // Restore original string
    token = strtok(config->ports, ",");
    int idx = 0;
    while (token) {
        char *dash = strchr(token, '-');
        if (dash) {
            int start = atoi(token);
            int end = atoi(dash + 1);
            for (int p = start; p <= end; p++) {
                config->port_list[idx++] = p;
            }
        } else {
            config->port_list[idx++] = atoi(token);
        }
        token = strtok(NULL, ",");
    }
}

// scan types example (S,N,F,X...)
void parse_scan_types(t_config *config) {
    if (!config->scans) {
        // Default to all scan types
        config->scan_type_count = 6;
        config->scan_types = malloc(config->scan_type_count * sizeof(char*));
        config->scan_types[0] = "SYN";
        config->scan_types[1] = "NULL";
        config->scan_types[2] = "FIN";
        config->scan_types[3] = "XMAS";
        config->scan_types[4] = "ACK";
        config->scan_types[5] = "UDP";
        return;
    }

    // Count scan types
    config->scan_type_count = 1;
    for (char *p = config->scans; *p; p++) {
        if (*p == ',') config->scan_type_count++;
    }

    // Allocate and fill scan types
    config->scan_types = malloc(config->scan_type_count * sizeof(char*));
    char *token = strtok(config->scans, ",");
    int i = 0;
    while (token) {
        config->scan_types[i++] = token;
        token = strtok(NULL, ",");
    }
}
