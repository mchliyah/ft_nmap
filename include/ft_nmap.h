#ifndef FT_NMAP_H
#define FT_NMAP_H

#include "./data_struct.h"

// function prototypes
void print_help();
void parse_args(int argc, char **argv, t_config *config);
void parse_ports(t_config *config);
void parse_scan_types(t_config *config);
void run_scan(t_config *config);
void *scan_thread(void *arg);
void *capture_responses_debug(void *arg);
const char* find_interface_for_target(const char *target_ip);
const char* get_interface_ip(const char *target_ip);
void init_scan();
void set_tcp_header(struct tcphdr *tcp, scan_type_t target_type);
void set_ip_header(struct ip *ip, const char *src_ip, struct sockaddr_in *target);
unsigned short csum(unsigned short *ptr, int nbytes);
void send_syn(int sock, struct sockaddr_in *target, const char *src_ip, int dest_port);
// void process_packet(unsigned char *buffer, int size);
void unblock_rst(int src_port);
void *start_listner(void *arg);
void *scan_thread(void *arg);
uint16_t generate_source_port();

#endif