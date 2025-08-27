#ifndef LINUX_COMPAT_H
#define LINUX_COMPAT_H

// Ensure errno is properly declared on macOS
#ifndef errno
extern int errno;
#endif

#ifdef __APPLE__
// This file provides Linux compatibility structures for macOS compilation

#include <stdint.h>

// Linux-style IP header structure
// Define our own struct to avoid conflicts with system headers
struct iphdr {
    uint8_t ihl:4;
    uint8_t version:4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

// Linux-style TCP header structure with both BSD and Linux field names
// We need to redefine this to have compatible field names for both styles
#define tcphdr tcphdr_linux
struct tcphdr_linux {
    uint16_t th_sport;   // source port (BSD style) - also accessible as 'source'
    uint16_t th_dport;   // destination port (BSD style) - also accessible as 'dest'
    uint32_t th_seq;     // sequence number (BSD style) - also accessible as 'seq'
    uint32_t th_ack;     // acknowledgment number (BSD style) - also accessible as 'ack_seq'
    uint16_t res1:4;
    uint16_t th_off:4;   // data offset (BSD style) - also accessible as 'doff'
    union {
        struct {
            uint16_t fin:1;      // Linux style flags
            uint16_t syn:1;
            uint16_t rst:1;
            uint16_t psh:1;
            uint16_t ack:1;
            uint16_t urg:1;
            uint16_t res2:2;
        };
        uint8_t th_flags;    // BSD style flags field
    };
    uint16_t th_win;     // window size (BSD style) - also accessible as 'window'
    uint16_t th_sum;     // checksum (BSD style) - also accessible as 'check'
    uint16_t th_urp;     // urgent pointer (BSD style) - also accessible as 'urg_ptr'
};

// Provide Linux-style field name aliases
#define source th_sport
#define dest th_dport
#define seq th_seq
#define ack_seq th_ack
#define doff th_off
#define window th_win
#define check th_sum
#define urg_ptr th_urp

#endif // __APPLE__

#endif // LINUX_COMPAT_H
