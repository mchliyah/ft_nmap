#include "libs.h"

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
    .scaner_on = 0, \
    .scan_complete = 0 \
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
    int scaner_on;
    int scan_complete;
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
} listner_args;

struct pseudo_header {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
    struct tcphdr tcp;
};