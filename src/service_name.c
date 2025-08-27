#include "../include/ft_nmap.h"

const char *get_service_by_port(int port) {
    switch (port) {
        case 21: return "ftp";
        case 22: return "ssh";
        case 23: return "telnet";
        case 25: return "smtp";
        case 53: return "domain";
        case 80: return "http";
        case 110: return "pop3";
        case 143: return "imap";
        case 443: return "https";
        case 465: return "smtps";
        case 587: return "submission";
        case 853: return "domain-s";
        case 993: return "imaps";
        case 995: return "pop3s";
        case 1433: return "ms-sql-s";
        case 3306: return "mysql";
        case 3389: return "rdp";
        case 5432: return "postgresql";
        case 6379: return "redis";
        case 8080: return "http-proxy";
        case 8443: return "https-alt";
        case 27017: return "mongodb";
        default: return NULL;
    }
}

const char *extract_service_from_payload(const unsigned char *payload, size_t payload_len, int port) {
    if (payload_len == 0) return NULL;
    
    size_t scan_len = payload_len > 1024 ? 1024 : payload_len;
    char *payload_str = malloc(scan_len + 1);
    if (!payload_str) return NULL;
    
    memcpy(payload_str, payload, scan_len);
    payload_str[scan_len] = '\0';

    for (size_t i = 0; i < scan_len; i++) {
        payload_str[i] = tolower(payload_str[i]);
    }
    
    const char *service = NULL;
    if (strstr(payload_str, "ssh-")) {
        service = "ssh";
    }
    else if (strstr(payload_str, "http/") || strstr(payload_str, "get ") || 
             strstr(payload_str, "post ") || strstr(payload_str, "host:") ||
             strstr(payload_str, "server:") || strstr(payload_str, "content-type:")) {
        service = "http";
    }
    else if (memcmp(payload, "\x16\x03", 2) == 0) {
        if (port == 443) service = "https";
        else if (port == 993) service = "imaps";
        else if (port == 995) service = "pop3s";
        else if (port == 465) service = "smtps";
        else if (port == 853) service = "domain-s";
        else service = "ssl";
    }
    else if (strstr(payload_str, "220") && (strstr(payload_str, "ftp") || 
             strstr(payload_str, "filezilla") || strstr(payload_str, "vsftpd"))) {
        service = "ftp";
    }
    else if (strstr(payload_str, "220") && (strstr(payload_str, "smtp") || 
             strstr(payload_str, "esmtp") || strstr(payload_str, "postfix"))) {
        service = "smtp";
    }
    else if (strstr(payload_str, "+ok") && strstr(payload_str, "pop3")) {
        service = "pop3";
    }
    else if (strstr(payload_str, "* ok") && strstr(payload_str, "imap")) {
        service = "imap";
    }
    else if (strstr(payload_str, "mysql")) {
        service = "mysql";
    }
    else if (strstr(payload_str, "postgres")) {
        service = "postgresql";
    }
    else if (strstr(payload_str, "redis")) {
        service = "redis";
    }
    else if (strstr(payload_str, "mongodb")) {
        service = "mongodb";
    }
    
    free(payload_str);
    return service;
}