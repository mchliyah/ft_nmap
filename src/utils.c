#include "../include/ft_nmap.h"

// Function to resolve hostname to IP address
char* resolve_hostname(const char* hostname) {
    struct addrinfo hints, *result;
    char* ip_str = NULL;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;
    
    int status = getaddrinfo(hostname, NULL, &hints, &result);
    if (status != 0) {
        fprintf(stderr, "Error: Failed to resolve hostname '%s': %s\n", 
                hostname, gai_strerror(status));
        return NULL;
    }
    
    if (result && result->ai_addr) {
        struct sockaddr_in* addr_in = (struct sockaddr_in*)result->ai_addr;
        ip_str = malloc(INET_ADDRSTRLEN);
        if (ip_str) {
            inet_ntop(AF_INET, &(addr_in->sin_addr), ip_str, INET_ADDRSTRLEN);
            printf("Resolved %s to %s\n", hostname, ip_str);
        }
    }
    
    freeaddrinfo(result);
    return ip_str;
}

// Function to check if a string is a valid IP address
int is_valid_ip(const char* str) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, str, &(sa.sin_addr)) == 1;
}

// Function to process IP or hostname and return IP address
char* process_target(const char* target) {
    if (is_valid_ip(target)) {
        // It's already an IP address, return a copy
        char* ip_copy = malloc(strlen(target) + 1);
        if (ip_copy) {
            strcpy(ip_copy, target);
        }
        return ip_copy;
    } else {
        // It's a hostname, resolve it
        return resolve_hostname(target);
    }
}

const char* get_interface_ip(const char *target_ip) {
    struct ifaddrs *ifaddr, *ifa;
    uint32_t target = inet_addr(target_ip);
    static char ip_str[INET_ADDRSTRLEN];
    
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return "10.0.0.78"; // fallback
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;
        
        // Skip loopback
        if (strcmp(ifa->ifa_name, "lo") == 0)
            continue;

        struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
        struct sockaddr_in *mask = (struct sockaddr_in *)ifa->ifa_netmask;

        // Check if target is in same subnet
        if (mask && (addr->sin_addr.s_addr & mask->sin_addr.s_addr) == 
            (target & mask->sin_addr.s_addr)) {
            inet_ntop(AF_INET, &addr->sin_addr, ip_str, INET_ADDRSTRLEN);
            freeifaddrs(ifaddr);
            return ip_str;
        }
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;
        if (strcmp(ifa->ifa_name, "lo") == 0)
            continue;
        
        struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
        inet_ntop(AF_INET, &addr->sin_addr, ip_str, INET_ADDRSTRLEN);
        freeifaddrs(ifaddr);
        return ip_str;
    }

    freeifaddrs(ifaddr);
    return "10.0.0.78"; // ultimate fallback
}


const char* find_interface_for_target(const char *target_ip) {
    struct ifaddrs *ifaddr, *ifa;
    uint32_t target = inet_addr(target_ip);
    char *best_iface = NULL;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return strdup("eth0");
    }

    // Check if target is localhost (127.0.0.1 or 127.x.x.x)
    if ((target & 0xFF) == 127) {
        freeifaddrs(ifaddr);
        return strdup("lo");
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;

        // Skip loopback for non-localhost targets
        if (strcmp(ifa->ifa_name, "lo") == 0)
            continue;

        struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
        struct sockaddr_in *mask = (struct sockaddr_in *)ifa->ifa_netmask;

        if (mask && (addr->sin_addr.s_addr & mask->sin_addr.s_addr) == 
            (target & mask->sin_addr.s_addr)) {
            best_iface = strdup(ifa->ifa_name);
            break;
        }
    }

    // Fallback to first non-loopback interface
    if (!best_iface) {
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
                continue;
            if (strcmp(ifa->ifa_name, "lo") == 0)
                continue;
            
            best_iface = strdup(ifa->ifa_name);
            break;
        }
    }

    freeifaddrs(ifaddr);
    return best_iface ? best_iface : strdup("eth0");
}


char *extract_udp_service_from_payload(const unsigned char *payload, size_t payload_len, uint16_t port) {
    if (!payload || payload_len == 0) {
        return NULL;
    }

    if (port == 53 && payload_len >= 12) {
        if (payload[2] & 0x80) {
            return strdup("dns");
        }
    }

    else if ((port == 67 || port == 68) && payload_len >= 240) {
        if (payload_len > 240 && 
            payload[236] == 0x63 && payload[237] == 0x82 && 
            payload[238] == 0x53 && payload[239] == 0x63) {
            return strdup("dhcp");
        }
    }

    else if (port == 161 && payload_len >= 2) {
        if (payload[0] == 0x30) {
            return strdup("snmp");
        }
    }

    else if (port == 123 && payload_len >= 48) {
        uint8_t version = (payload[0] >> 3) & 0x07;
        uint8_t mode = payload[0] & 0x07;
        if (version >= 1 && version <= 4 && mode >= 1 && mode <= 5) {
            return strdup("ntp");
        }
    }

    else if (port == 137 && payload_len >= 12) {
        if (payload[2] & 0x80) {
            return strdup("netbios-ns");
        }
    }
    else if (port == 69 && payload_len >= 4) {
        uint16_t opcode = (payload[0] << 8) | payload[1];
        if (opcode >= 1 && opcode <= 5) {
            return strdup("tftp");
        }
    }

    else if (port == 111 && payload_len >= 28) {
        uint32_t msg_type = (payload[4] << 24) | (payload[5] << 16) | (payload[6] << 8) | payload[7];
        uint32_t rpc_version = (payload[8] << 24) | (payload[9] << 16) | (payload[10] << 8) | payload[11];
        if (msg_type == 1 && rpc_version == 2) {
            return strdup("rpcbind");
        }
    }

    else if (port == 1434 && payload_len > 0) {
        if (payload[0] == 0x05) {
            return strdup("ms-sql-m");
        }
    }
    else if ((port == 1812 || port == 1813) && payload_len >= 20) {
        uint8_t code = payload[0];
        if (code >= 1 && code <= 13) {
            return strdup("radius");
        }
    }
    
    else if (port == 5060 && payload_len > 8) {
        if (strncmp((char*)payload, "SIP/2.0", 7) == 0) {
            return strdup("sip");
        }
    }

    else {
        if (payload_len > 4 && strncmp((char*)payload, "HTTP", 4) == 0) {
            return strdup("http");
        }
        if (payload_len > 3 && isdigit(payload[0]) && isdigit(payload[1]) && isdigit(payload[2])) {
            return strdup("ftp");
        }
        
        if (payload_len > 4 && strncmp((char*)payload, "SSH-", 4) == 0) {
            return strdup("ssh");
        }
    }

    return NULL;
}


void add_port(int port, int state) {
    t_port *new_port = malloc(sizeof(t_port));
    if (!new_port) {
        perror("Failed to allocate memory for new port");
        exit(EXIT_FAILURE);
    }
    new_port->port = port;
    new_port->state = state;
    new_port->to_print = false;
    new_port->tcp_udp = "tcp";
    new_port->service = get_service_by_port(port);
    new_port->reason = NULL;
    new_port->next = NULL;

    pthread_mutex_lock(&g_config.port_mutex);
    if (!g_config.port_list) {
        g_config.port_list = new_port;
    } else {
        t_port *current = g_config.port_list;
        while (current->next) {
            current = current->next;
        }
        current->next = new_port;
    }
    g_config.port_count++;
    pthread_mutex_unlock(&g_config.port_mutex);
}

// Function to read IPs from file
char** read_ips_from_file(const char* filename, int* count) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error: Could not open file '%s': %s\n", filename, strerror(errno));
        return NULL;
    }
    
    char **ips = NULL;
    char line[256];
    *count = 0;
    
    // First pass: count lines
    while (fgets(line, sizeof(line), file)) {
        // Remove trailing newline and whitespace
        line[strcspn(line, "\r\n")] = 0;
        
        // Skip empty lines and comments
        if (strlen(line) == 0 || line[0] == '#') {
            continue;
        }
        
        (*count)++;
    }
    
    if (*count == 0) {
        fprintf(stderr, "Error: No valid IP addresses found in file '%s'\n", filename);
        fclose(file);
        return NULL;
    }
    
    // Allocate memory for IP array
    ips = malloc(*count * sizeof(char*));
    if (!ips) {
        fprintf(stderr, "Error: Failed to allocate memory for IP addresses\n");
        fclose(file);
        return NULL;
    }
    
    // Second pass: read IPs
    rewind(file);
    int index = 0;
    while (fgets(line, sizeof(line), file) && index < *count) {
        // Remove trailing newline and whitespace
        line[strcspn(line, "\r\n")] = 0;
        
        // Skip empty lines and comments
        if (strlen(line) == 0 || line[0] == '#') {
            continue;
        }
        
        // Try to resolve hostname/IP
        char* resolved_ip = process_target(line);
        if (!resolved_ip) {
            fprintf(stderr, "Warning: Failed to resolve target '%s', skipping\n", line);
            continue;
        }
        
        // Allocate and store resolved IP
        ips[index] = resolved_ip;
        index++;
    }
    
    *count = index; // Update count to actual number of valid IPs
    fclose(file);
    
    if (*count == 0) {
        free(ips);
        fprintf(stderr, "Error: No valid IP addresses found in file '%s'\n", filename);
        return NULL;
    }
    
    printf("Successfully loaded %d IP address(es) from file '%s'\n", *count, filename);
    return ips;
}

// Function to free IP array
void free_ip_array(char** ips, int count) {
    if (!ips) return;
    
    for (int i = 0; i < count; i++) {
        if (ips[i]) {
            free(ips[i]);
        }
    }
    free(ips);
}


const char* get_current_time_short() {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    static char buffer[26];
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    return buffer;
}

const char* get_scan_type_name() {
    if (g_config.scan_types.syn) return "SYN Stealth";
    if (g_config.scan_types.null) return "NULL";
    if (g_config.scan_types.fin) return "FIN";
    if (g_config.scan_types.xmas) return "XMAS";
    if (g_config.scan_types.ack) return "ACK";
    if (g_config.scan_types.udp) return "UDP";
    return "Unknown";
}

const char* get_reverse_dns(const char *ip) {
    // Simplified implementation - replace with actual rDNS lookup
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        return "invalid-ip";
    }
    
    struct hostent *host = gethostbyaddr(&addr, sizeof(addr), AF_INET);
    if (host) {
        return host->h_name;
    }
    
    return "unknown";
}

void print_scan_statistics() {
    int open_ports = 0, filtered_ports = 0, closed_ports = 0;
    t_port *current = g_config.port_list;
    
    while (current) {
        if (current->state == STATE_OPEN) open_ports++;
        else if (current->state == STATE_FILTERED) filtered_ports++;
        else if (current->state == STATE_CLOSED) closed_ports++;
        current = current->next;
    }
    
    V_PRINT(1, "Not shown: %d filtered %s\n", filtered_ports, 
           filtered_ports == 1 ? "port" : "ports");

    if (g_config.verbose) {
        printf("Raw packets sent: %d | Rcvd: %d\n", g_config.packets_sent, g_config.packets_received);
    }
}