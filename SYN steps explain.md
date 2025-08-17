Nmap SYN scans, also known as half-open scans, utilize the TCP three-way handshake to probe for open ports on a target system. The process involves sending SYN packets to target ports and analyzing the responses to determine if the port is open, closed, or filtered without completing the full handshake. This method is efficient and stealthy, minimizing the chance of detection by intrusion detection systems. 
Here's a breakdown of the steps and packet headers involved:

1. SYN Packet Transmission:
Nmap sends a TCP SYN (synchronize) packet to the target port. 
The packet header includes:
Source IP address: The IP address of the machine running Nmap. 
Destination IP address: The IP address of the target machine. 
Source Port: A randomly chosen high port number. 
Destination Port: The target port being scanned. 
SYN flag: Set to 1, indicating a request to establish a connection. 
Other TCP header fields (e.g., sequence number, window size) are set with appropriate initial values. 

2. Response Analysis:
Open Port:
If the target port is open, the target machine responds with a TCP SYN-ACK packet. 
The SYN-ACK packet includes:
Source IP address: The target's IP address. 
Destination IP address: The scanner's IP address. 
Source Port: The target port being scanned. 
Destination Port: The scanner's source port. 
SYN flag: Set to 1. 
ACK flag: Set to 1, acknowledging the SYN packet. 
Closed Port:
If the target port is closed, the target machine responds with a TCP RST (reset) packet. 
The RST packet includes:
Source IP address: The target's IP address. 
Destination IP address: The scanner's IP address. 
Source Port: The target port being scanned. 
Destination Port: The scanner's source port. 
RST flag: Set to 1, indicating the connection is being reset. 
Filtered Port:
If the target port is filtered (e.g., by a firewall), there may be no response, or a timeout may occur. 

3. Connection Termination (Half-Open):
Nmap, in a SYN scan, does not complete the TCP three-way handshake by sending an ACK to acknowledge the SYN-ACK. 
Instead, Nmap often sends a TCP RST packet to the target port to reset the connection and avoid creating a full TCP connection. This is what makes the scan "half-open" and more stealthy. 
In some cases, Nmap may not send a RST, and the operating system on the scanner may send it automatically. 
In summary: The SYN scan uses the initial stage of the TCP handshake to determine port status without completing the connection. It sends a SYN packet, analyzes the response (SYN-ACK for open, RST for closed), and then terminates the connection attempt, making it a stealthy and efficient scanning technique. 