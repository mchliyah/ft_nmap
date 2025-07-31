#include "../include/ft_nmap.h"

void print_help(void) {
    printf("Usage: ./ft_nmap [OPTIONS]\n");
    printf("Options:\n");
    printf("  --help\t\t\tShow this help message\n");
    printf("  --ports [LIST/RANGE]\t\tPorts to scan (e.g. 22,80,443 or 20-80)\n");
    printf("  --ip [IP]\t\t\tIP address to scan\n");
    printf("  --file [filename]\t\tRead IPs from file\n");
    printf("  --speedup [N]\t\t\tNumber of threads (max 250)\n");
    printf("  --scan [TYPES]\t\tScan types: SYN, NULL, FIN, XMAS, ACK, UDP\n");
    exit(0);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Missing arguments. Use --help for usage.\n");
        return 1;
    }

    // values
    char *ip = NULL;
    char *file = NULL;
    char *ports = NULL;
    char *scans = NULL;
    int speedup = 0;

    // arguments

    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"ip", required_argument, 0, 'i'},
        {"ports", required_argument, 0, 'p'},
        {"file", required_argument, 0, 'f'},
        {"scan", required_argument, 0, 's'},
        {"speedup", required_argument, 0, 'S'},
        {0, 0, 0, 0}
    };


    int opt;
    while ((opt = getopt_long(argc, argv, "hi:p:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                print_help();
                break;
            case 'i':
                ip = optarg;
                printf("IP address set to: %s\n", ip);
                break;
            case 'p':
                ports = optarg;
                break;
            case 'f':
                file = optarg;
                break;
            case 's':
                scans = optarg;
                break;
            case 'S':
                speedup = atoi(optarg);
                if (speedup < 1 || speedup > 250) {
                    fprintf(stderr, "Speedup must be between 1 and 250.\n");
                    return 1;
                }
                break;
            default:
                fprintf(stderr, "Unknown option: %c\n", opt);
                return 1;
        }
    }
    // for (int i = 1; i < argc; i++) {
    //     if (strcmp(argv[i], "--help") == 0) {
    //         print_help();
    //     } else if (strcmp(argv[i], "--ip") == 0 && i + 1 < argc) {
    //         ip = argv[++i];
    //     } else if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) {
    //         file = argv[++i];
    //     } else if (strcmp(argv[i], "--ports") == 0 && i + 1 < argc) {
    //         ports = argv[++i];
    //     } else if (strcmp(argv[i], "--scan") == 0 && i + 1 < argc) {
    //         scans = argv[++i];
    //     } else if (strcmp(argv[i], "--speedup") == 0 && i + 1 < argc) {
    //         speedup = atoi(argv[++i]);
    //         if (speedup > 250) {
    //             fprintf(stderr, "Speedup too high (max 250).\n");
    //             return 1;
    //         }
    //     } else {
    //         fprintf(stderr, "Unknown or invalid argument: %s\n", argv[i]);
    //         return 1;
    //     }
    // }

    // Validation
    if (!ip && !file) {
        fprintf(stderr, "You must specify --ip or --file.\n");
        return 1;
    }

    // Print configuration (for now)
    printf("Scan Configurations:\n");
    if (ip) printf("Target IP: %s\n", ip);
    if (file) printf("Input File: %s\n", file);
    printf("Ports: %s\n", ports ? ports : "1-1024 (default)");
    printf("Scan types: %s\n", scans ? scans : "All");
    printf("Speedup (threads): %d\n", speedup);

    printf("Scanning..\n");

    // TODO: Add scanning logic

    return 0;
}
