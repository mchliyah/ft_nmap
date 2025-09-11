#include "libs.h"
#include "verbose.h"
#include "init_default.h"

struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t unused;
};


typedef struct {
    const char *name;
    int         has_arg;
    int         *flag;
    int         val;
} t_option;

typedef struct t_scan_types {
    scan_type syn;
    scan_type ack;
    scan_type fin;
    scan_type null;
    scan_type xmas;
    scan_type udp;
} scan_type_t;

typedef struct t_port{
    int         port;
    port_state  state;
    const char *service;
    const char *tcp_udp;
    const char *reason;
    bool        to_print;
    struct t_port *next;
} t_port;

typedef struct ips
{
    bool is_up;
    char *ip;
    char *resolve_hostname;
    t_port *port_list;
    struct ips *next;
} t_ips;

typedef struct {
    char *ip;
    t_ips *ips;
    int ip_count;
    int up_hosts;
    char *file;
    char *ports;
    bool is_port_default;
    char *scans;
    int verbose;
    int reason;
    int speedup;
    int port_count;
    int scan_type_count;
    int scan_complete;
    int timeout;
    int ports_per_thread;
    const char *src_ip;
    int packets_sent;
    int packets_received;
    t_port *port_list;
    scan_type_t scan_types;
    time_t scan_start_time;
    pthread_cond_t cond;
    pthread_mutex_t port_mutex;
    pthread_mutex_t print_mutex;
    pthread_mutex_t socket_mutex;
} t_config;

typedef struct {
    int sock;
    int thread_id;
    t_ips *ips;
    t_port *current;
    int start_range;
    int end_range;
    struct sockaddr_in target;
} scan_thread_data;

typedef struct {
    int port;
    struct sockaddr_in target;
    int state;
    uint16_t src_port;
    uint32_t sent_seq;
} listner_args;

struct pseudo_header {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
    struct tcphdr tcp;
};

typedef struct {
    uint16_t port;
    const char *service;
    const uint8_t *payload;
    size_t payload_len;
} udp_payload_t;
