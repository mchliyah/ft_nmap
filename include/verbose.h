#ifndef VERBOSE_H
#define VERBOSE_H

#include "./libs.h"

// Verbosity macro definitions
#define V_PRINT(level, fmt, ...) \
    do { \
        if (g_config.verbose >= (level)) { \
            pthread_mutex_lock(&g_config.print_mutex); \
            printf(fmt, ##__VA_ARGS__); \
            pthread_mutex_unlock(&g_config.print_mutex); \
        } \
    } while (0)

// Error verbosity macro definition
#define V_PRINT_ERR(level, fmt, ...) \
    do { \
        if (g_config.verbose >= (level)) { \
            pthread_mutex_lock(&g_config.print_mutex); \
            fprintf(stderr, fmt, ##__VA_ARGS__); \
            pthread_mutex_unlock(&g_config.print_mutex); \
        } \
    } while (0)

// fprintf custum error printing ligne and error message for debug purpose
#define PRINT_DEBUG(fmt, ...) \
    do { \
            pthread_mutex_lock(&g_config.print_mutex); \
            fprintf(stderr, "DEBUG : %s:%d:%s(): \n" fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
            pthread_mutex_unlock(&g_config.print_mutex); \
    } while (0)


// #define INIT_SCAN()
//     do { 
//         g_config.speedup = (g_config.speedup < 1) ? 1 : 
//         (g_config.speedup > 250) ? 250 : g_config.speedup; 
//         srand(time(NULL)); 
//         g_config.scan_start_time = time(NULL); 
//         g_config.src_ip = get_interface_ip(g_config.ip); 
//         printf("Nmap scan report for %snn", g_config.ip); 
//     } while(0)
    #endif