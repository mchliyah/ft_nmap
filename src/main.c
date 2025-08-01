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

int main(int argc, char **argv) {

    t_config config = INIT_CONFIG();
    // t_config config;
    // memset(&config, 0, sizeof(t_config));

    parse_args(argc, argv, &config);

    // Print configuration (for now)
    printf("Scan Configurations:\n");
    if (config.ip) printf("Target IP: %s\n", config.ip);
    if (config.file) printf("Input File: %s\n", config.file);
    printf("Ports: %s\n", config.ports ? config.ports : "1-1024 (default)");
    printf("Scan types: %s\n", config.scans ? config.scans : "All");
    printf("Speedup (threads): %d\n", config.speedup);

    // Prepare and Run the scan
    run_scan(&config);

    // Cleanup
    if (config.port_list) free(config.port_list);
    if (config.scan_types) free(config.scan_types);

    return 0;
}
