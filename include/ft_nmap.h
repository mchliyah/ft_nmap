#ifndef FT_NMAP_H
#define FT_NMAP_H

#include "./data_struct.h"

// Declare g_config as extern
extern t_config g_config;

// Function prototypes
void print_help();
void print_complete_scan();
void print_scan_result(int port, port_state_t state, scan_type_t scan_type);
void parse_args(int argc, char **argv);
void parse_ports();
void parse_scan_types();
void run_scan();
void *scan_thread(void *arg);
const char* find_interface_for_target(const char *target_ip);
const char* get_interface_ip(const char *target_ip);
void init_scan();
void set_tcp_header(struct tcphdr *tcp, scan_type_t target_type);
void set_ip_header(struct ip *ip, const char *src_ip, struct sockaddr_in *target);

void set_psudo_header(struct pseudo_header *psh, const char *src_ip, struct sockaddr_in *target);
unsigned short csum(unsigned short *ptr, int nbytes);
void send_syn(int sock, struct sockaddr_in *target, char *datagram);
void *start_listner();
void *scan_thread(void *arg);
uint16_t generate_source_port();
void add_port(int port, scan_type_t scan_type);
void print_debug(void);

#endif