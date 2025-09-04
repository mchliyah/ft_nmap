#ifndef VERBOSE_H
#define VERBOSE_H

#include "./libs.h"

#define V_PRINT(level, fmt, ...) \
    do { \
        if (g_config.verbos >= (level)) { \
            pthread_mutex_lock(&g_config.print_mutex); \
            printf(fmt, ##__VA_ARGS__); \
            pthread_mutex_unlock(&g_config.print_mutex); \
        } \
    } while (0)

#define V_PRINT_ERR(level, fmt, ...) \
    do { \
        if (g_config.verbos >= (level)) { \
            pthread_mutex_lock(&g_config.print_mutex); \
            fprintf(stderr, fmt, ##__VA_ARGS__); \
            pthread_mutex_unlock(&g_config.print_mutex); \
        } \
    } while (0)

#endif