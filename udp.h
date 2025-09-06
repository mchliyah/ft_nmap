#ifndef UDP_SCANNER_H
#define UDP_SCANNER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <errno.h>
#include <signal.h>

#define MAX_PORTS 65535
#define MAX_THREADS 100
#define PACKET_TIMEOUT 2
#define CAPTURE_FILTER "icmp or udp"
#define SNAP_LEN 1518

// ICMP definitions for compatibility
#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH 3
#endif
#ifndef ICMP_PORT_UNREACH
#define ICMP_PORT_UNREACH 3
#endif

// ICMP header structure
struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t unused;
};

// UDP scan results
typedef enum {
    PORT_OPEN,
    PORT_CLOSED,
    PORT_FILTERED,
    PORT_UNKNOWN
} port_status_t;

// Port scan result structure
typedef struct {
    uint16_t port;
    port_status_t status;
    char service_name[32];
} scan_result_t;

// Thread data structure for packet sending
typedef struct {
    char *target_ip;
    uint16_t *ports;
    int port_count;
    int thread_id;
    int raw_socket;
} sender_thread_data_t;

// Global scanner context
typedef struct {
    char *target_ip;
    uint16_t *ports;
    int port_count;
    int thread_count;
    pcap_t *pcap_handle;
    scan_result_t *results;
    pthread_mutex_t results_mutex;
    volatile int scan_complete;
    struct timeval scan_start_time;
} scanner_context_t;

// Function prototypes
int create_raw_socket(void);
int send_udp_probe(int raw_socket, const char *target_ip, uint16_t port);
void *packet_listener_thread(void *arg);
void *packet_sender_thread(void *arg);
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void process_icmp_response(const u_char *packet, int packet_len, scanner_context_t *ctx);
void process_udp_response(const u_char *packet, int packet_len, scanner_context_t *ctx);
uint16_t calculate_checksum(uint16_t *buf, int len);
int setup_pcap_listener(const char *interface, pcap_t **handle);
void print_scan_results(scanner_context_t *ctx);
void cleanup_scanner(scanner_context_t *ctx);
int parse_port_range(const char *port_str, uint16_t **ports, int *count);
const char *get_service_name(uint16_t port);
void signal_handler(int sig);

// Global scanner context for signal handling
extern scanner_context_t *g_scanner_ctx;

#endif // UDP_SCANNER_H