#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

// configuration
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
} t_config;