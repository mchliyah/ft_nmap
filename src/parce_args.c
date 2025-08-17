#include "../include/ft_nmap.h"


static const t_option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"ip", required_argument, NULL, 'i'},
    {"ports", required_argument, NULL, 'p'},
    {"file", required_argument, NULL, 'f'},
    {"scan", required_argument, NULL, 's'},
    {"speedup", required_argument, NULL, 'S'},
    {NULL, 0, NULL, 0}
};

void parse_args(int argc, char **argv, t_config *config) {
    
    if (argc < 2) {
        print_help();
        exit(1);
    }
    int opt;
    while ((opt = getopt_long(argc, argv, "hi:p:f:s:S:", 
           (struct option *)long_options, NULL)) != -1) {
        switch (opt) {
            case 'h': print_help(); exit(0);
            case 'i': config->ip = optarg; break;
            case 'p': config->ports = optarg; break;
            case 'f': config->file = optarg; break;
            case 's': config->scans = optarg; break;
            case 'S': config->speedup = atoi(optarg); break;
            default: print_help(); exit(1);
        }
    }
    // Validation
    if (!config->ip && !config->file) {
        fprintf(stderr, "Specify --ip or --file\n");
        exit(1);
    }
}