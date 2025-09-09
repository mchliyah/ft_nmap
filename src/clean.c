
#include "../include/ft_nmap.h"

void free_ip_list(t_ips *ip_list) {
    while (ip_list) {
        t_ips *temp = ip_list;
        ip_list = ip_list->next;
        
        free(temp->ip);
        free(temp->resolve_hostname);
        // free_ports()
        t_port *port = temp->port_list;
        while (port) {
            t_port *port_temp = port;
            port = port->next;
            free(port_temp);
        }
        
        free(temp);
    }
}

// void cleanup_ports(void) {
//     t_port *current = g_config.port_list;
//     while (current) {
//         t_port *next = current->next;
//         free(current);
//         current = next;
//     }
// }
