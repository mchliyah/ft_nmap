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

#endif