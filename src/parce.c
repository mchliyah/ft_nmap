#include "../include/ft_nmap.h"

static const t_option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"ip", required_argument, NULL, 'i'},
    {"ports", required_argument, NULL, 'p'},
    {"file", required_argument, NULL, 'f'},
    {"scan", required_argument, NULL, 's'},
    {"speedup", required_argument, NULL, 'S'},
    {"verbose", no_argument, NULL, 'v'},
    {"reason", no_argument, NULL, 'r'},
    {NULL, 0, NULL, 0}
};

static int add_ip_to_list(char ***ip_list, int *count, char *ip) {
    char **new_list = realloc(*ip_list, (*count + 1) * sizeof(char*));
    if (!new_list) {
        perror("realloc");
        return 0;
    }
    
    new_list[*count] = strdup(ip);
    if (!new_list[*count]) {
        perror("strdup");
        return 0;
    }
    
    *ip_list = new_list;
    (*count)++;
    return 1;
}

void parse_args(int argc, char **argv) {
    if (argc < 2) {
        print_help();
        exit(1);
    }
    
    int opt;
    char **ip_list = NULL;
    int ip_count = 0;
    
    while ((opt = getopt_long(argc, argv, "hi:p:f:s:S:vr", 
           (struct option *)long_options, NULL)) != -1) {
        switch (opt) {
            case 'h': print_help(); exit(0);
            case 'i': {
                char* resolved_ip = process_target(optarg);
                if (!resolved_ip) {
                    fprintf(stderr, "Error: Failed to resolve target '%s'\n", optarg);
                    exit(1);
                }
                if (!add_ip_to_list(&ip_list, &ip_count, resolved_ip)) {
                    free(resolved_ip);
                    exit(1);
                }
                free(resolved_ip);
                break;
            }
            case 'v': 
                printf("Increasing verbosity level to %d\n", g_config.verbose + 1);
                g_config.verbose++; 
                break;
            case 'r': g_config.reason = 1; break;
            case 'p': g_config.ports = optarg; break;
            case 'f': {
                int file_ip_count = 0;
                char **file_ips = read_ips_from_file(optarg, &file_ip_count);
                if (!file_ips) {
                    exit(1);
                }
                for (int i = 0; i < file_ip_count; i++) {
                    if (!add_ip_to_list(&ip_list, &ip_count, file_ips[i])) {
                        // Clean up on error
                        for (int j = 0; j < file_ip_count; j++) free(file_ips[j]);
                        free(file_ips);
                        for (int j = 0; j < ip_count; j++) free(ip_list[j]);
                        free(ip_list);
                        exit(1);
                    }
                    free(file_ips[i]);
                }
                free(file_ips);
                break;
            }
            case 's': g_config.scans = optarg; break;
            case 'S': g_config.speedup = atoi(optarg); break;
            default: print_help(); exit(1);
        }
    }

    while (optind < argc) {
        char* resolved_ip = process_target(argv[optind]);
        if (!resolved_ip) {
            fprintf(stderr, "Error: Failed to resolve target '%s'\n", argv[optind]);
            for (int i = 0; i < ip_count; i++) free(ip_list[i]);
            free(ip_list);
            exit(1);
        }
        if (!add_ip_to_list(&ip_list, &ip_count, resolved_ip)) {
            free(resolved_ip);
            for (int i = 0; i < ip_count; i++) free(ip_list[i]);
            free(ip_list);
            exit(1);
        }
        free(resolved_ip);
        optind++;
    }

    if (ip_count == 0 && !g_config.file) {
        fprintf(stderr, "Specify --ip or --file\n");
        exit(1);
    }

    g_config.ip_list = ip_list;
    g_config.ip_count = ip_count;
    
    if (ip_count > 0) {
        g_config.ip = ip_list[0];
    }
}

void add_port_scantype(int p){
    g_config.scan_types.udp && SCAN_UDP ? add_port(p, STATE_OPEN_FILTERED): NULL;
    g_config.scan_types.syn && SCAN_SYN ? add_port(p, STATE_FILTERED): NULL;
    g_config.scan_types.null && SCAN_NULL ? add_port(p, STATE_OPEN): NULL;
    g_config.scan_types.fin && SCAN_FIN ? add_port(p, STATE_OPEN): NULL;
    g_config.scan_types.xmas && SCAN_XMAS ? add_port(p, STATE_OPEN): NULL;
    g_config.scan_types.ack && SCAN_ACK ? add_port(p, STATE_FILTERED): NULL;
    !g_config.scan_type_count? add_port(p, STATE_FILTERED) : NULL;
}
void parse_ports() {
    if (!g_config.ports) {
        V_PRINT(1, "No ports specified, defaulting to 1-1024\n");
        g_config.ports = DEFAULT_PORTS;
        g_config.is_port_default = true;
        g_config.scan_type_count = 1;
    }

    char *token = strtok(g_config.ports, ",");
    while (token) {
        char *dash = strchr(token, '-');
        if (dash) {
            int start = atoi(token);
            int end = atoi(dash + 1);
            for (int p = start; p <= end; p++) add_port_scantype(p);
        } else add_port_scantype(atoi(token));
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
        if      (strcmp(token, "S") == 0 || strcmp(token, "SYN") == 0) g_config.scan_types.syn = SCAN_SYN;
        else if (strcmp(token, "N") == 0 || strcmp(token, "NULL") == 0) g_config.scan_types.null = SCAN_NULL;
        else if (strcmp(token, "F") == 0 || strcmp(token, "FIN") == 0) g_config.scan_types.fin = SCAN_FIN;
        else if (strcmp(token, "X") == 0 || strcmp(token, "XMAS") == 0) g_config.scan_types.xmas = SCAN_XMAS;
        else if (strcmp(token, "A") == 0 || strcmp(token, "ACK") == 0) g_config.scan_types.ack = SCAN_ACK;
        else if (strcmp(token, "U") == 0 || strcmp(token, "UDP") == 0) g_config.scan_types.udp = SCAN_UDP;
        else {
            fprintf(stderr, "Unknown scan type: %s\n", token);
            fprintf(stderr, "Supported scan types: SYN (S), NULL (N), FIN (F), XMAS (X), ACK (A), UDP (U)\n");
            exit(EXIT_FAILURE);
        }
        g_config.scan_type_count++;
        
        token = strtok(NULL, ",");
    }
}

