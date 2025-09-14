
#include "../include/ft_nmap.h"

void free_ip_list(t_ips *ip_list) {
    while (ip_list) {
        t_ips *temp = ip_list;
        ip_list = ip_list->next;
        
        free(temp->ip);
        free(temp->resolve_hostname);
        t_port *port = temp->port_list;
        while (port) {
            t_port *port_temp = port;
            port = port->next;
            if (port_temp->reason) free(port_temp->reason);
            if (port_temp->service) free(port_temp->service);
            free(port_temp);
        }
        
        free(temp);
    }
}