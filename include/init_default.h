#ifndef INTI_DEFAULT_
#define INIT_DEFAULT_h
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
    .file                =  NULL, \
    .ports               =  NULL, \
    .scans               =  NULL, \
    .port_list           =  NULL, \
    .is_port_default     = false, \
    .verbose             =  0,    \
    .reason              =  0,    \
    .ip_count            =  0,    \
    .up_hosts            =  0,    \
    .speedup             =  0,    \
    .port_count          =  0,    \
    .scan_type_count     =  0,    \
    .scan_complete       =  0,    \
    .scan_start_time     =  0,    \
    .timeout             =  5,   \
    .packets_sent        =  0,    \
    .packets_received    =  0,    \
    .scan_types          =  INIT_SCAN_TYPES(), \
    .cond                =  PTHREAD_COND_INITIALIZER, \
    .port_mutex          =  PTHREAD_MUTEX_INITIALIZER, \
    .print_mutex         =  PTHREAD_MUTEX_INITIALIZER, \
    .socket_mutex        =  PTHREAD_MUTEX_INITIALIZER \
}

#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH 3
#endif
#ifndef ICMP_PORT_UNREACH
#define ICMP_PORT_UNREACH 3
#endif
#endif