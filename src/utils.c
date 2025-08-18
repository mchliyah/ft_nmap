#include "../include/ft_nmap.h"

void block_rst(int src_port) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "iptables -A OUTPUT -p tcp --tcp-flags RST RST "
             "--sport %d -j DROP",
             src_port);
    int s = system(cmd);
    if (s == -1)
        return;
}

void unblock_rst(int src_port) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "iptables -D OUTPUT -p tcp --tcp-flags RST RST "
             "--sport %d -j DROP",
             src_port);
    int s = system(cmd);
    if (s == -1)
        return;
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

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;

        // Skip loopback
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
