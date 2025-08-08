#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>
#include <pcap.h>

// configuration
#define INIT_CONFIG() { \
    .ip = NULL,         \
    .file = NULL,       \
    .ports = NULL,      \
    .scans = NULL,      \
    .speedup = 0,       \
    .port_list = NULL,  \
    .port_count = 0,    \
    .scan_types = NULL, \
    .scan_type_count = 0 \
}

typedef struct {
    char *ip ;
    char *file;
    char *ports;
    char *scans;
    int speedup;
    int *port_list;
    int port_count;
    char **scan_types;
    int scan_type_count;
} t_config;

typedef struct {
    int thread_id;
    t_config *config;
    int start_port;
    int end_port;
} scan_thread_data;

typedef struct {
    const char *name;
    int has_arg;
    int *flag;
    int val;
} t_option;

// function prototypes
void print_help();
void parse_args(int argc, char **argv, t_config *config);
void parse_ports(t_config *config);
void parse_scan_types(t_config *config);
void *scan_thread(void *arg);
void run_scan(t_config *config);