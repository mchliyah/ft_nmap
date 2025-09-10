<!-- REASON should not be printed in this case -->
```bash
sudo ./ft_nmap -i 8.8.8.8 -v
```
Increasing verbosity level to 1
No ports specified, defaulting to 1-1024
Starting ft_nmap at Wed Sep 10 11:41:05 2025
Scanning 1 IP address(es)
Ports: 0-1024
Nmap scan report for 1 ip Scanning 8.8.8.8
Initiating Parallel DNS resolution of 1 host
Parallel DNS resolution completed in 0.00 seconds
Starting listener on interface ens5
Initializing SYN Stealth scan at 2025-09-10 11:41:05
Scanning 8.8.8.8 [1025 ports]
DEBUG : src/scan.c:59:start_sender_threads(): 
start range : 0 end range : 1025 remaining 0 
Starting scan of ports 0 to 1025 now
Discovered open port 53/tcp on 8.8.8.8
Discovered open port 443/tcp on 8.8.8.8
Discovered open port 853/tcp on 8.8.8.8
Completed scanning 1025 ports
Completed SYN Stealth Scan for 8.8.8.8 at Wed Sep 10 11:41:05 2025
, 1.00s elapsed (1025 total ports)
Completed SYN Stealth Scan at Wed Sep 10 11:41:05 2025
, 11.00s elapsed (1025 total ports)
PORT       STATE        SERVICE      REASON
53/tcp   open         domain       syn-ack ttl 112
443/tcp   open         https        syn-ack ttl 122
853/tcp   open         domain-s     syn-ack ttl 122
Not shown: 0 filtered ports
Raw packets sent: 1025 | Rcvd: 1140