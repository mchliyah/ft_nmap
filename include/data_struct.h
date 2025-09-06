#include "libs.h"
#include "verbose.h"

// scan types

typedef enum scan_type {

    SCAN_SYN  = 1,
    SCAN_ACK  = 2,
    SCAN_FIN  = 4,
    SCAN_NULL = 8,
    SCAN_XMAS = 16,
    SCAN_UDP  = 32
} scan_type ;

// port states

typedef enum port_state {
    STATE_WAITING   = 1,
    STATE_OPEN      = 2,
    STATE_CLOSED    = 3,
    STATE_FILTERED  = 4,
    STATE_OPEN_FILTERED = 5
} port_state ;


// defaults values
#define P_SIZE          65535
#define MAX_SCAN_TYPES  6
#define DEFAULT_SPEEDUP 10
#define DEFAULT_PORTS   "0-1024"
#define DEFAULT_SCANS   "S"


#define INIT_SCAN_TYPES() {         \
    .syn                  =  0,     \
    .ack                  =  0,     \
    .fin                  =  0,     \
    .null                 =  0,     \
    .xmas                 =  0,     \
    .udp                  =  0      \
}

// configuration
#define INIT_CONFIG() {           \
    .ip                  =  NULL, \
    .ip_list             =  NULL, \
    .file                =  NULL, \
    .ports               =  NULL, \
    .scans               =  NULL, \
    .port_list           =  NULL, \
    .verbose             =  0,    \
    .reason              =  0,    \
    .ip_count            =  0,    \
    .speedup             =  0,   \
    .port_count          =  0,    \
    .scan_type_count     =  0,    \
    .scan_complete       =  0,    \
    .scan_start_time     =  0,    \
    .timeout             =  10,    \
    .packets_sent        =  0,    \
    .packets_received    =  0,    \
    .scan_types          =  INIT_SCAN_TYPES(), \
    .cond                =  PTHREAD_COND_INITIALIZER, \
    .port_mutex          =  PTHREAD_MUTEX_INITIALIZER, \
    .print_mutex         =  PTHREAD_MUTEX_INITIALIZER, \
    .socket_mutex        =  PTHREAD_MUTEX_INITIALIZER \
}

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



typedef struct {
    char *ip;
    char **ip_list;
    int ip_count;
    char *file;
    char *ports;
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
