```bash
sudo ./ft_nmap -i 8.8.8.8 -sU
```
Couldn't parse filter icmp or udp and host: can't parse filter expression: syntax error
Nmap scan report for 1 ip

<!--  -->
```bash
sudo ./ft_nmap -i 8.8.8.8 -p 443 -sN
```
DEBUG : src/scan.c:59:start_sender_threads(): 
start range : 0 end range : 1 remaining 0 
Nmap scan report for 1 ip PORT       STATE        SERVICE
443/tcp   open         https


<!--  -->
```bash
sudo ./ft_nmap -i 8.8.8.8 -p 443 -sX
```
DEBUG : src/scan.c:59:start_sender_threads(): 
start range : 0 end range : 1 remaining 0 
Nmap scan report for 1 ip PORT       STATE        SERVICE
443/tcp   open         https

<!--  -->
```bash
sudo ./ft_nmap -i 8.8.8.8 -p 443 -sA
```
DEBUG : src/scan.c:59:start_sender_threads(): 
start range : 0 end range : 1 remaining 0 
Nmap scan report for 1 ip PORT       STATE        SERVICE
443/tcp   open         https

<!--  -->
```bash
sudo ./ft_nmap -i 8.8.8.8 -p 443 -sF
```
DEBUG : src/scan.c:59:start_sender_threads(): 
start range : 0 end range : 1 remaining 0 
Nmap scan report for 1 ip PORT       STATE        SERVICE
443/tcp   open         https

<!--  -->
