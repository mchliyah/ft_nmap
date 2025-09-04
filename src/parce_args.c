#include "../include/ft_nmap.h"

static const t_option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"ip", required_argument, NULL, 'i'},
    {"ports", required_argument, NULL, 'p'},
    {"file", required_argument, NULL, 'f'},
    {"scan", required_argument, NULL, 's'},
    {"speedup", required_argument, NULL, 'S'},
    {"verbose", no_argument, NULL, 'v'},
    {NULL, 0, NULL, 0}
};

void parse_args(int argc, char **argv) {
    
    if (argc < 2) {
        print_help();
        exit(1);
    }
    
    int opt;
    int ip_mode = 0; // Track if we're collecting IPs
    
    while ((opt = getopt_long(argc, argv, "hi:p:f:s:S:v", 
           (struct option *)long_options, NULL)) != -1) {
        switch (opt) {
            case 'h': print_help(); exit(0);
            case 'i': {
                // Process the target (could be IP or hostname)
                char* resolved_ip = process_target(optarg);
                if (!resolved_ip) {
                    fprintf(stderr, "Error: Failed to resolve target '%s'\n", optarg);
                    exit(1);
                }
                g_config.ip = resolved_ip; 
                ip_mode = 1;
                break;
            }
            case 'v': 
            {
                printf("Increasing verbosity level to %d\n", g_config.verbos + 1);
                g_config.verbos++; 
                break;
            }
            case 'p': g_config.ports = optarg; break;
            case 'f': g_config.file = optarg; break;
            case 's': g_config.scans = optarg; break;
            case 'S': g_config.speedup = atoi(optarg); break;
            default: print_help(); exit(1);
        }
    }

    // If we're in IP mode and there are remaining arguments, they are additional IPs
    if (ip_mode && optind < argc) {
        // Count total IPs (first one + remaining arguments)
        int total_ips = 1 + (argc - optind);

        // Allocate array for IP strings
        char **ip_list = malloc(total_ips * sizeof(char*));
        if (!ip_list) {
            fprintf(stderr, "Error: Failed to allocate memory for IP list\n");
            exit(1);
        }

        // Store first IP
        ip_list[0] = malloc(strlen(g_config.ip) + 1);
        strcpy(ip_list[0], g_config.ip);
        
        // Store additional IPs/hostnames
        for (int i = 1; i < total_ips; i++) {
            char* resolved_ip = process_target(argv[optind + i - 1]);
            if (!resolved_ip) {
                fprintf(stderr, "Error: Failed to resolve target '%s'\n", argv[optind + i - 1]);
                // Clean up previously allocated IPs
                for (int j = 0; j < i; j++) {
                    free(ip_list[j]);
                }
                free(ip_list);
                exit(1);
            }
            ip_list[i] = resolved_ip;
        }
        
        // Store in config
        g_config.ip_list = ip_list;
        g_config.ip_count = total_ips;
        
        // Set first IP as current for compatibility
        g_config.ip = ip_list[0];
    } else if (ip_mode) {
        // Single IP case
        g_config.ip_list = malloc(sizeof(char*));
        g_config.ip_list[0] = malloc(strlen(g_config.ip) + 1);
        strcpy(g_config.ip_list[0], g_config.ip);
        g_config.ip_count = 1;
    }
    
    // Validation
    if (!g_config.ip && !g_config.file) {
        fprintf(stderr, "Specify --ip or --file\n");
        exit(1);
    }
}