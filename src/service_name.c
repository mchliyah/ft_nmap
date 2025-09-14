#include "../include/ft_nmap.h"

char *get_service_by_port(int port) {
    const char *name = NULL;
    switch (port) {
        case 21: name = "ftp"; break;
        case 22: name = "ssh"; break;
        case 23: name = "telnet"; break;
        case 25: name = "smtp"; break;
        case 53: name = "domain"; break;
        case 80: name = "http"; break;
        case 110: name = "pop3"; break;
        case 143: name = "imap"; break;
        case 443: name = "https"; break;
        case 465: name = "smtps"; break;
        case 587: name = "submission"; break;
        case 853: name = "domain-s"; break;
        case 993: name = "imaps"; break;
        case 995: name = "pop3s"; break;
        case 1433: name = "ms-sql-s"; break;
        case 3306: name = "mysql"; break;
        case 3389: name = "rdp"; break;
        case 5432: name = "postgresql"; break;
        case 6379: name = "redis"; break;
        case 8080: name = "http-proxy"; break;
        case 8443: name = "https-alt"; break;
        case 27017: name = "mongodb"; break;
        default: name = NULL; break;
    }
    if (name) return strdup(name);
    return NULL;
}

char *extract_service_from_payload(const unsigned char *payload, size_t payload_len, int port) {
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
    if (service) return strdup(service);
    return NULL;
}