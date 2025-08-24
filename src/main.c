#include "../include/ft_nmap.h"

// Define g_config in main.c
t_config g_config = INIT_CONFIG();

void init_scan() {
    // Ensure speedup is within valid range
    g_config.speedup = (g_config.speedup < 1) ? 1 : 
    (g_config.speedup > 250) ? 250 : g_config.speedup;

    srand(time(NULL));
    g_config.scan_start_time = time(NULL);
    g_config.src_ip = get_interface_ip(g_config.ip);
    printf("Starting ft_nmap at %s\n", ctime(&g_config.scan_start_time));
    printf("Nmap scan report for %s\n\n", g_config.ip);
}

void scan_single_ip(const char* target_ip) {
    // Set current target IP and source IP
    g_config.ip = (char*)target_ip;  // Cast away const for compatibility
    g_config.src_ip = get_interface_ip(target_ip);
    
    // Reset scan state for this IP
    g_config.scan_start_time = time(NULL);
    g_config.scan_complete = 0;
    
    printf("Nmap scan report for %s\n\n", target_ip);
    
    // Run the scan for this IP
    run_scan();
    print_scan_result();
}

int main(int argc, char **argv) {

    //parce data
    parse_args(argc, argv);
    // fprintf(stderr, "Parsed arguments successfully\n");
    parse_scan_types();
    // fprintf(stderr, "Parsed scan types successfully\n");
    parse_ports();
    // fprintf(stderr, "Parsed ports successfully\n");

    //print check for data config
    // print_debug();
    // fprintf(stderr, "Finished printing debug information\n");

    // Initialize scan configuration
    // Ensure speedup is within valid range
    g_config.speedup = (g_config.speedup < 1) ? 1 : 
    (g_config.speedup > 250) ? 250 : g_config.speedup;

    srand(time(NULL));
    printf("Starting ft_nmap at %s\n", ctime(&g_config.scan_start_time));
    
    // Handle multiple IPs from command line or file
    if (g_config.ip_list && g_config.ip_count > 0) {
        // Multiple IPs from command line
        for (int i = 0; i < g_config.ip_count; i++) {
            scan_single_ip(g_config.ip_list[i]);
            if (i < g_config.ip_count - 1) {
                printf("\n");
            }
        }
        
        // Clean up IP list
        for (int i = 0; i < g_config.ip_count; i++) {
            free(g_config.ip_list[i]);
        }
        free(g_config.ip_list);
        
    } else if (g_config.file) {
        // Read IPs from file and scan each one
        int ip_count = 0;
        char** ips = read_ips_from_file(g_config.file, &ip_count);
        
        if (!ips || ip_count == 0) {
            fprintf(stderr, "Error: Failed to read IP addresses from file '%s'\n", g_config.file);
            return 1;
        }
        
        printf("Starting scan of %d IP address(es) from file '%s'\n", ip_count, g_config.file);
        
        // Scan each IP
        for (int i = 0; i < ip_count; i++) {
            scan_single_ip(ips[i]);
            if (i < ip_count - 1) {
                printf("\n");
            }
        }
        
        // Clean up
        free_ip_array(ips, ip_count);
        
    } else if (g_config.ip) {
        // Single IP scan
        init_scan();
        run_scan();
        print_scan_result();
    } else {
        fprintf(stderr, "Error: No IP address or file specified\n");
        return 1;
    }

    // Clean up ports
    t_port *current = g_config.port_list;
    while (current) {
        t_port *next = current->next;
        free(current);
        current = next;
    }

    return 0;
}
