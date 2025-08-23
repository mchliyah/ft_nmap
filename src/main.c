#include "../include/ft_nmap.h"

// Define g_config in main.c
t_config g_config = INIT_CONFIG();

void init_scan() {
    // Ensure speedup is within valid range
    g_config.speedup = (g_config.speedup < 1) ? 1 : 
    (g_config.speedup > 250) ? 250 : g_config.speedup;

    printf("config speedup = %d\n end config !\n\n\n", g_config.speedup);

    srand(time(NULL));
    g_config.scan_start_time = time(NULL);
    g_config.scaner_on = 1;
    g_config.src_ip = get_interface_ip(g_config.ip);
}
int main(int argc, char **argv) {

    //parce data
    parse_args(argc, argv);
    fprintf(stderr, "Parsed arguments successfully\n");
    parse_scan_types();
    fprintf(stderr, "Parsed scan types successfully\n");
    parse_ports();
    fprintf(stderr, "Parsed ports successfully\n");

    //print check for data config
    print_debug();
    fprintf(stderr, "Finished printing debug information\n");

    // Initialize scan configuration
    init_scan();
    run_scan();
    print_scan_result();
    t_port *current = g_config.port_list;
    while (current) {
        t_port *next = current->next;
        free(current);
        current = next;
    }

    return 0;
}
