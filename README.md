## 📡 ft_nmap — Custom Port Scanner in C

## docker envierment 
- make build
- make run_docker
will spown a root shell 


**ft_nmap** is a custom-built port scanner inspired by the popular tool [nmap](https://nmap.org/). Written entirely in C, this project is part of the 42 Network curriculum and focuses on low-level networking, packet manipulation, and multithreaded programming using the `libpcap` and `pthread` libraries.

The scanner supports various types of scans (SYN, NULL, FIN, XMAS, ACK, UDP) and can scan multiple ports on one or more IPv4 addresses with customizable speed using threads.

The goal of the project is to understand:

- How network packets are crafted and transmitted
- How different scanning techniques are implemented
- How to optimize network operations using multithreading
- How to interpret and display scan results clearly
