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
#include <limits.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>

typedef enum {
    STATE_WAITING,
    STATE_OPEN,
    STATE_CLOSED,
    STATE_FILTERED
} port_state_t;

// defaults values
#define MAX_PORTS 65535
#define MAX_SCAN_TYPES 6
#define DEFAULT_SPEEDUP 10
#define DEFAULT_PORTS "1-1024"
#define DEFAULT_SCANS "S"

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
    .scan_type_count = 0, \
    .mutex = PTHREAD_MUTEX_INITIALIZER, \
    .cond = PTHREAD_COND_INITIALIZER, \
    .listner_thread_done = 0, \
}

typedef struct {
    const char *name;
    int has_arg;
    int *flag;
    int val;
} t_option;

typedef struct {
    char *ip;
    char *file;
    char *ports;
    char *scans;
    int speedup;
    int *port_list;
    int port_count;
    char **scan_types;
    int scan_type_count;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int listner_thread_done;
} t_config;

typedef struct {
    int thread_id;
    t_config *config;
    int start_port;
    int end_port;
} scan_thread_data;

typedef struct {
    t_config *config;
    int port;
    struct sockaddr_in target;
    port_state_t state;
    uint16_t src_port;
    uint32_t sent_seq;
} capture_thread_args;

// function prototypes
void print_help();
void parse_args(int argc, char **argv, t_config *config);
void parse_ports(t_config *config);
void parse_scan_types(t_config *config);
void run_scan(t_config *config);
void *scan_thread(void *arg);
void *capture_responses(void *arg);
void *capture_responses_debug(void *arg);
const char* find_interface_for_target(const char *target_ip);
const char* get_interface_ip(const char *target_ip);
void init_scan();