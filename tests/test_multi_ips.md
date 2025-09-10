<!--  -->
```bash
sudo ./ft_nmap -i 8.8.8.8 9.9.9.9 -p 443
```
DEBUG : src/scan.c:59:start_sender_threads(): 
start range : 0 end range : 1 remaining 0 
Nmap scan report for 2 ip PORT       STATE        SERVICE
443/tcp   open         https


<!-- in print -->
```bash
sudo ./ft_nmap -i 8.8.8.8 -p 443,53
```
DEBUG : src/scan.c:59:start_sender_threads(): 
start range : 0 end range : 2 remaining 0 
Nmap scan report for 1 ip PORT       STATE        SERVICE
443/tcp   open         https
53/tcp   open         domain
