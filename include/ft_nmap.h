#ifndef FT_NMAP_H
#define FT_NMAP_H

#include "./data_struct.h"

// Declare g_config as extern
extern t_config g_config;

// Function prototypes
void print_help();
void parse_ports();
void parse_scan_types();
void run_scan();
void print_complete_scan();
void print_scan_result();
void parse_args(int argc, char **argv);
void *scan_thread(void *arg);
const char* find_interface_for_target(const char *target_ip);
const char* get_interface_ip(const char *target_ip);
void init_scan();
void scan_single_ip(const char* target_ip);
void handle_multi_ip_scan();
void handle_file_scan();
void handle_single_ip_scan();
void initialize_config();
void cleanup_ports();
void set_tcp_header(struct tcphdr *tcp, scan_type target_type);
void set_ip_header(struct ip *ip, const char *src_ip, struct sockaddr_in *target);

void set_psudo_header(struct pseudo_header *psh, const char *src_ip, struct sockaddr_in *target);
unsigned short csum(unsigned short *ptr, int nbytes);
uint16_t calculate_tcp_checksum(struct ip *ip, struct tcphdr *tcp, uint8_t *options, int options_len);
void *start_listner();
uint16_t generate_source_port();
void add_port(int port, int state);
const char *port_state_to_string(int state);
void print_debug(void);
char** read_ips_from_file(const char* filename, int* count);
void free_ip_array(char** ips, int count);

// hostname resolution functions
char* resolve_hostname(const char* hostname);
int is_valid_ip(const char* str);
char* process_target(const char* target);

// service 

const char *get_service_by_port(int port);
const char *extract_service_from_payload(const unsigned char *payload, size_t payload_len, int port);   


const char* get_current_time_short();
const char* get_scan_type_name();
const char* get_current_time();
double get_elapsed_time();
const char* get_reverse_dns(const char *ip);
#endif