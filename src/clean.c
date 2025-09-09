
#include "../include/ft_nmap.h"

void cleanup_ips(void) {
    for (int i = 0; i < g_config.ip_count; i++) {
        free(g_config.ip_list[i]);
    }
    free(g_config.ip_list);
}

void cleanup_ports(void) {
    t_port *current = g_config.port_list;
    while (current) {
        t_port *next = current->next;
        free(current);
        current = next;
    }
}
