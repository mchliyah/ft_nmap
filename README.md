## 📡 ft_nmap — Custom Port Scanner in C  
```to be optimized later```

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


## some of code steps 

1. parce config ip port and type
   - port range if multiple (0 - 1024 default )
   - scan types default SYN 
   - ip target must be set or looping from file
2. starting  a thread litner which will catch respences form target
   - sending correct packet with corect packet triger server to respond and so 
     the listner parce packet to define the port targetet (OPEN, CLOSE, ...)
3. sending packets to triger the server target (based on  speedup value max 250)
   - default speedup value set to 0 , in this case the programe will use one thread
     to send all ports targeted
   - speedup make ports deviding by thread (200 port to scan with 10 speedup example ) 
     -> 2 ports per thread to send 
{to seabch later if we may create many listners to procces packets sens the listner will procces recived packets } 


### UDP


UDP scans are more challenging than TCP scans because UDP is a connectionless protocol that doesn't use handshakes like TCP. UDP scans work by sending UDP packets to target ports and analyzing the responses (or lack thereof) to determine if the port is open, closed, or filtered. This method is less reliable than TCP scanning but is essential for discovering UDP services.

## Step-by-Step Process:

### 1. UDP Packet Transmission:

The scanner sends a UDP packet to the target port.
**Packet header includes:**

- **Source IP address**: The IP address of the machine running the scanner
- **Destination IP address**: The IP address of the target machine
- **Source Port**: A randomly chosen high port number (typically 32768-65535)
- **Destination Port**: The target port being scanned
- **UDP Length**: The length of the UDP header plus data (minimum 8 bytes)
- **UDP Checksum**: Checksum for error detection
- **Data payload**: Usually empty, but may contain protocol-specific data

### 2. Response Analysis:

#### **Open Port Response:**

If the target port is open and a UDP service is listening:

- **Response**: UDP packet containing service-specific data
- **Response packet includes:**
  - Source IP: Target's IP address
  - Destination IP: Scanner's IP address
  - Source Port: Target port being scanned
  - Destination Port: Scanner's source port
  - Service data: Protocol-specific response (DNS, SNMP, etc.)

#### **Closed Port Response:**

If the target port is closed:

- **Response**: ICMP "Port Unreachable" message (Type 3, Code 3)
- **ICMP packet includes:**
  - ICMP Type: 3 (Destination Unreachable)
  - ICMP Code: 3 (Port Unreachable)
  - Original packet data: Portion of the original UDP packet

#### **Open|Filtered Port (No Response):**

If no response is received:

- **Could indicate:**
  - Open port: Service running but doesn't respond to empty packets
  - Filtered port: Firewall dropping packets silently
- **Scanner behavior**: Retransmit packet, wait for timeout

#### **Filtered Port Response:**

If the port is filtered by a firewall:

- **Response**: ICMP "Administratively Prohibited" (Type 3, Code 13)
- **Or**: No response at all (timeout)

### 3. Special Considerations:

#### **Rate Limiting:**

- Many systems rate-limit ICMP responses
- Affects scan speed and accuracy
- May cause false "open|filtered" results

#### **Service Detection:**

For better accuracy, UDP scans often include:

- **DNS query** for port 53
- **SNMP request** for port 161
- **NTP request** for port 123
- **Protocol-specific payloads** to trigger known services

## Common UDP Services and Expected Responses:

| Port  | Service | Typical Response           |
| ----- | ------- | -------------------------- |
| 53    | DNS     | DNS response packet        |
| 67/68 | DHCP    | DHCP response              |
| 69    | TFTP    | TFTP error or data packet  |
| 123   | NTP     | NTP timestamp response     |
| 161   | SNMP    | SNMP response              |
| 514   | Syslog  | Usually no response        |
| 1194  | OpenVPN | Protocol-specific response |

## Summary:

UDP scanning relies on sending UDP packets and analyzing ICMP error messages or service responses. The lack of a connection state makes UDP scans inherently less reliable than TCP scans, often requiring multiple retransmissions and longer timeouts for accurate results.


### SYN

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



# XMAS

XMAS scans are a type of TCP stealth scan that sends TCP packets with multiple flags set simultaneously: FIN, PSH, and URG flags (and sometimes others). The name "XMAS" comes from the fact that the packet is "lit up like a Christmas tree" with multiple flags set. Like NULL and FIN scans, XMAS scans exploit RFC 793 behavior for stealth reconnaissance.

## Step-by-Step Process:

### 1. XMAS Packet Transmission:

The scanner sends a TCP packet with FIN, PSH, and URG flags set to the target port.
**Packet header includes:**

- **Source IP address**: The IP address of the machine running the scanner
- **Destination IP address**: The IP address of the target machine
- **Source Port**: A randomly chosen high port number
- **Destination Port**: The target port being scanned
- **TCP Flags**: FIN + PSH + URG SET (SYN=0, ACK=0, FIN=1, RST=0, PSH=1, URG=1)
- **Sequence Number**: Random value
- **Acknowledgment Number**: Usually 0
- **Window Size**: Typically set to a reasonable value
- **Urgent Pointer**: May be set to a non-zero value
- **Checksum**: Calculated including TCP pseudo-header

### 2. Flag Combination Explanation:

#### **FIN Flag (Finish):**

- **Purpose**: Indicates no more data from sender
- **Normal Use**: Connection termination
- **In XMAS**: Combined with other flags for unusual packet

#### **PSH Flag (Push):**

- **Purpose**: Requests immediate data delivery
- **Normal Use**: Force buffered data transmission
- **In XMAS**: Creates abnormal flag combination

#### **URG Flag (Urgent):**

- **Purpose**: Indicates urgent data in packet
- **Normal Use**: Priority data handling
- **In XMAS**: Combined unusually with FIN and PSH

### 3. Response Analysis:

#### **Open Port Response:**

If the target port is open:

- **Expected Response**: NO RESPONSE (packet is ignored)
- **Scanner Interpretation**: Port is OPEN or FILTERED
- **RFC 793 Behavior**: Open ports ignore packets with unusual flag combinations

#### **Closed Port Response:**

If the target port is closed:

- **Response**: TCP RST (Reset) packet
- **RST packet includes:**
  - Source IP: Target's IP address
  - Destination IP: Scanner's IP address
  - Source Port: Target port being scanned
  - Destination Port: Scanner's source port
  - RST flag: Set to 1
  - ACK flag: May also be set to 1

#### **Filtered Port Response:**

If the port is filtered by a firewall:

- **Response**: ICMP "Destination Unreachable" message
- **Or**: No response (timeout)
- **Common ICMP responses:**
  - Type 3, Code 1: Host Unreachable
  - Type 3, Code 2: Protocol Unreachable
  - Type 3, Code 3: Port Unreachable
  - Type 3, Code 9, 10, 13: Communication Administratively Prohibited

### 4. Scan Logic:

#### **State Determination:**

- **OPEN**: No response received (timeout)
- **CLOSED**: RST packet received
- **FILTERED**: ICMP error message received

#### **Detection Principle:**

- **Abnormal Packets**: Flag combination is highly unusual
- **RFC Exploitation**: Leverages standard TCP stack behavior
- **Response Patterns**: Same as NULL and FIN scans

### 5. Advantages and Limitations:

#### **Advantages:**

- **High Stealth**: Very unusual packet, may evade simple filters
- **Firewall Bypass**: Some firewalls don't inspect unusual flag combinations
- **IDS Evasion**: May bypass signature-based detection
- **Distinctive**: Easy to identify in packet captures for testing
- **RFC Compliance**: Exploits standard TCP behavior

#### **Limitations:**

- **Highly Detectable**: Unusual flag combination is very suspicious
- **System Dependent**: Not all TCP stacks handle it identically
- **Ambiguous Results**: Cannot distinguish open from filtered reliably
- **Modern Detection**: Most modern IDS/IPS detect XMAS scans easily
- **Windows Issues**: Windows systems may not respond predictably

### 6. Security Implications:

#### **Detection Signatures:**

XMAS scans are easily detected by:

- **Flag Pattern**: FIN+PSH+URG combination is abnormal
- **IDS Rules**: Common signature in intrusion detection systems
- **Firewall Logs**: Unusual traffic patterns
- **Network Monitoring**: Stands out in traffic analysis

#### **Evasion Techniques:**

- **Timing Variation**: Randomize scan timing
- **Source Spoofing**: Use different source IPs (where possible)
- **Fragmentation**: Fragment packets to evade detection
- **Decoy Scans**: Mix with legitimate traffic

### 7. Comparison with Other Stealth Scans:

#### **XMAS vs NULL:**

- **Detectability**: XMAS more detectable due to multiple flags
- **Behavior**: Both exploit same RFC principle
- **Implementation**: XMAS has specific flag combination

#### **XMAS vs FIN:**

- **Complexity**: XMAS uses multiple flags vs single FIN flag
- **Detection**: XMAS more easily spotted in logs
- **Effectiveness**: Similar results, different signatures

#### **XMAS vs SYN:**

- **Speed**: SYN faster and more reliable
- **Stealth**: XMAS more stealthy but less reliable
- **Practicality**: SYN preferred for actual reconnaissance

### 8. Practical Implementation:

#### **Packet Structure:**

```
IP Header:
- Version: 4
- Protocol: 6 (TCP)
- Source/Destination IPs

TCP Header:
- Source/Destination Ports
- Sequence Number: Random
- Acknowledgment: 0
- Flags: FIN|PSH|URG (0x29)
- Window Size: 1024
- Urgent Pointer: May be set
- Checksum: Calculated
```

#### **Response Processing:**

- **RST Detection**: Parse incoming RST packets
- **Timeout Handling**: Manage open/filtered ambiguity
- **ICMP Processing**: Handle firewall responses
- **Logging**: Record scan results and responses

### 9. Use Cases:

#### **Security Testing:**

- **IDS Testing**: Verify detection capabilities
- **Firewall Testing**: Test rule effectiveness
- **Penetration Testing**: Initial reconnaissance phase

#### **Research and Education:**

- **TCP Stack Testing**: Verify RFC 793 compliance
- **Network Analysis**: Understand traffic patterns
- **Security Training**: Demonstrate attack techniques

#### **Forensics:**

- **Attack Attribution**: Identify scanning techniques
- **Timeline Analysis**: Reconstruct attack sequences
- **Evidence Collection**: Document scanning attempts

## Summary:

XMAS scans send TCP packets with FIN, PSH, and URG flags set simultaneously, creating an unusual "Christmas tree" effect. They exploit RFC 793 behavior where closed ports respond with RST while open ports ignore abnormal packets. While providing stealth capabilities, XMAS scans are highly detectable by modern security systems due to their distinctive flag combination.


# NULL 


NULL scans are a type of TCP stealth scan that sends TCP packets with no flags set (all flags are 0). This scan type exploits the behavior defined in RFC 793, where a closed port should respond with a RST packet, while an open port should ignore the packet. NULL scans are useful for evading certain firewall and IDS detection mechanisms.

## Step-by-Step Process:

### 1. NULL Packet Transmission:

The scanner sends a TCP packet with NO flags set to the target port.
**Packet header includes:**

- **Source IP address**: The IP address of the machine running the scanner
- **Destination IP address**: The IP address of the target machine
- **Source Port**: A randomly chosen high port number
- **Destination Port**: The target port being scanned
- **TCP Flags**: ALL FLAGS SET TO 0 (SYN=0, ACK=0, FIN=0, RST=0, PSH=0, URG=0)
- **Sequence Number**: Random initial value
- **Window Size**: Typically set to a reasonable value
- **Checksum**: Calculated including TCP pseudo-header

### 2. Response Analysis:

#### **Open Port Response:**

If the target port is open:

- **Expected Response**: NO RESPONSE (packet is ignored)
- **Scanner Interpretation**: Port is OPEN or FILTERED
- **Reason**: Open ports ignore packets with no flags per RFC 793

#### **Closed Port Response:**

If the target port is closed:

- **Response**: TCP RST (Reset) packet
- **RST packet includes:**
  - Source IP: Target's IP address
  - Destination IP: Scanner's IP address
  - Source Port: Target port being scanned
  - Destination Port: Scanner's source port
  - RST flag: Set to 1
  - ACK flag: May also be set to 1

#### **Filtered Port Response:**

If the port is filtered by a firewall:

- **Response**: ICMP "Destination Unreachable" message
- **Or**: No response (timeout)
- **ICMP types that may be received:**
  - Type 3, Code 1: Host Unreachable
  - Type 3, Code 2: Protocol Unreachable
  - Type 3, Code 3: Port Unreachable
  - Type 3, Code 9, 10, 13: cc

### 3. Scan Logic:

#### **State Determination:**

- **OPEN**: No response received (timeout)
- **CLOSED**: RST packet received
- **FILTERED**: ICMP error message received

#### **Timing Considerations:**

- Longer timeouts needed since open ports don't respond
- Multiple retransmissions may be required
- Rate limiting considerations for accurate results

### 4. Advantages and Limitations:

#### **Advantages:**

- **Stealth**: Avoids TCP handshake completion
- **Firewall Evasion**: Some firewalls don't inspect packets with no flags
- **IDS Evasion**: May bypass simple signature-based detection
- **RFC Compliance**: Exploits standard TCP behavior

#### **Limitations:**

- **Ambiguous Results**: Cannot distinguish between open and filtered ports reliably
- **System Dependent**: Some systems don't follow RFC 793 strictly
- **Slower**: Requires timeouts for open port detection
- **Less Reliable**: Windows systems may not respond as expected

### 5. Detection and Countermeasures:

#### **Detection Methods:**

- **Packet Analysis**: Packets with all flags = 0 are unusual
- **Pattern Recognition**: Multiple NULL packets to different ports
- **Timing Analysis**: Scan timing patterns

#### **Common Countermeasures:**

- **Stateful Firewalls**: Drop packets that don't belong to established connections
- **IDS/IPS**: Detect and alert on NULL scan patterns
- **TCP Stack Hardening**: Configure systems to handle unusual packets differently

### 6. Use Cases:

#### **Penetration Testing:**

- **Firewall Testing**: Verify firewall rule effectiveness
- **IDS Testing**: Test intrusion detection capabilities
- **Service Discovery**: Identify services on unusual ports

#### **Network Reconnaissance:**

- **Stealth Scanning**: Minimize detection risk
- **Compliance Testing**: Verify RFC 793 compliance
- **Security Assessment**: Identify potential security gaps

## Summary:

NULL scans exploit TCP RFC behavior by sending packets with no flags set. Closed ports respond with RST packets, while open ports typically ignore the packets. This creates ambiguity between open and filtered ports but provides a stealthy method for port scanning that may evade certain security mechanisms.



# FIN Scan Steps Explanation

FIN scans are a type of TCP stealth scan that sends TCP packets with only the FIN (Finish) flag set. Like NULL scans, FIN scans exploit RFC 793 behavior where closed ports should respond with RST packets, while open ports should ignore packets that don't belong to an established connection. FIN scans are useful for firewall evasion and stealthy reconnaissance.

## Step-by-Step Process:

### 1. FIN Packet Transmission:

The scanner sends a TCP packet with only the FIN flag set to the target port.
**Packet header includes:**

- **Source IP address**: The IP address of the machine running the scanner
- **Destination IP address**: The IP address of the target machine
- **Source Port**: A randomly chosen high port number
- **Destination Port**: The target port being scanned
- **TCP Flags**: ONLY FIN FLAG SET (SYN=0, ACK=0, FIN=1, RST=0, PSH=0, URG=0)
- **Sequence Number**: Random value (as if from an established connection)
- **Window Size**: Typically set to a reasonable value
- **Checksum**: Calculated including TCP pseudo-header

### 2. Response Analysis:

#### **Open Port Response:**

If the target port is open:

- **Expected Response**: NO RESPONSE (packet is ignored)
- **Scanner Interpretation**: Port is OPEN or FILTERED
- **Reason**: Open ports ignore FIN packets that don't belong to established connections

#### **Closed Port Response:**

If the target port is closed:

- **Response**: TCP RST (Reset) packet
- **RST packet includes:**
  - Source IP: Target's IP address
  - Destination IP: Scanner's IP address
  - Source Port: Target port being scanned
  - Destination Port: Scanner's source port
  - RST flag: Set to 1
  - ACK flag: May also be set to 1
  - Sequence number: Usually acknowledges the FIN packet

#### **Filtered Port Response:**

If the port is filtered by a firewall:

- **Response**: ICMP "Destination Unreachable" message
- **Or**: No response (timeout)
- **ICMP error types:**
  - Type 3, Code 1: Host Unreachable
  - Type 3, Code 2: Protocol Unreachable
  - Type 3, Code 3: Port Unreachable
  - Type 3, Code 9, 10, 13: Communication Administratively Prohibited

### 3. Scan Logic:

#### **State Determination:**

- **OPEN**: No response received after timeout
- **CLOSED**: RST packet received
- **FILTERED**: ICMP error message received

#### **FIN Flag Behavior:**

- **Purpose**: FIN flag normally indicates connection termination
- **Exploitation**: Sending FIN to non-established connection
- **RFC 793**: Closed ports must respond with RST

### 4. Advantages and Limitations:

#### **Advantages:**

- **Stealth**: Doesn't attempt connection establishment
- **Firewall Bypass**: Some firewalls allow FIN packets through
- **IDS Evasion**: May appear as normal connection termination
- **Simple Implementation**: Single packet per port
- **RFC Compliance**: Exploits standard TCP behavior

#### **Limitations:**

- **Ambiguous Results**: Cannot reliably distinguish open from filtered
- **System Variations**: Not all systems follow RFC 793 strictly
- **Windows Compatibility**: Windows systems may respond differently
- **Timeout Dependency**: Requires waiting for timeouts on open ports
- **Rate Limiting**: May be affected by ICMP rate limiting

### 5. Comparison with Other Scans:

#### **FIN vs NULL Scan:**

- **Similarity**: Both exploit same RFC 793 behavior
- **Difference**: FIN has one flag set, NULL has no flags
- **Detection**: FIN may appear more "normal" than NULL

#### **FIN vs SYN Scan:**

- **Stealth**: FIN is more stealthy (no connection attempt)
- **Reliability**: SYN is more reliable and faster
- **Detection**: SYN scans are more easily detected

### 6. Firewall and IDS Considerations:

#### **Firewall Behavior:**

- **Stateless Firewalls**: May allow FIN packets through
- **Stateful Firewalls**: Should block FIN packets without established connection
- **Rule Bypass**: May bypass simple port-blocking rules

#### **IDS Detection:**

- **Signature Detection**: FIN scans have detectable patterns
- **Anomaly Detection**: Multiple FIN packets to different ports
- **Timing Analysis**: Scan timing patterns are recognizable

### 7. Practical Implementation:

#### **Packet Construction:**

```
IP Header:
- Version: 4
- Protocol: 6 (TCP)
- Source/Destination IPs

TCP Header:
- Source/Destination Ports
- Sequence Number: Random
- Acknowledgment: 0
- Flags: FIN (0x01)
- Window Size: 1024 (typical)
- Checksum: Calculated
```

#### **Response Handling:**

- **Listen for RST**: Indicates closed port
- **Timeout Management**: Handle open/filtered ambiguity
- **ICMP Processing**: Detect filtered ports

### 8. Use Cases:

#### **Security Testing:**

- **Firewall Rule Testing**: Verify stateful filtering
- **IDS Capability Testing**: Test detection mechanisms
- **Compliance Verification**: Check RFC 793 implementation

#### **Reconnaissance:**

- **Service Discovery**: Identify listening services
- **Network Mapping**: Understand network topology
- **Vulnerability Assessment**: Find potential attack vectors

## Summary:

FIN scans send TCP packets with only the FIN flag set, exploiting RFC 793 behavior where closed ports respond with RST while open ports ignore the packets. This provides a stealthy scanning method that may bypass certain firewalls and IDS systems, though results can be ambiguous between open and filtered ports.




# ACK Scan Steps Explanation

ACK scans are a specialized type of TCP scan that sends TCP packets with only the ACK (Acknowledgment) flag set. Unlike other scan types that primarily determine if ports are open or closed, ACK scans are designed to map firewall rules and determine which ports are filtered or unfiltered. ACK scans don't reliably determine if ports are open, but they excel at firewall reconnaissance.

## Step-by-Step Process:

### 1. ACK Packet Transmission:

The scanner sends a TCP packet with only the ACK flag set to the target port.
**Packet header includes:**

- **Source IP address**: The IP address of the machine running the scanner
- **Destination IP address**: The IP address of the target machine
- **Source Port**: A randomly chosen high port number
- **Destination Port**: The target port being scanned
- **TCP Flags**: ONLY ACK FLAG SET (SYN=0, ACK=1, FIN=0, RST=0, PSH=0, URG=0)
- **Sequence Number**: Random value
- **Acknowledgment Number**: Random value (pretending to acknowledge data)
- **Window Size**: Typically set to a reasonable value
- **Checksum**: Calculated including TCP pseudo-header

### 2. Response Analysis:

#### **Unfiltered Port Response:**

If the port is unfiltered (whether open or closed):

- **Response**: TCP RST packet
- **RST packet includes:**
  - Source IP: Target's IP address
  - Destination IP: Scanner's IP address
  - Source Port: Target port being scanned
  - Destination Port: Scanner's source port
  - RST flag: Set to 1
- **Interpretation**: Port is UNFILTERED (firewall allows traffic through)
- **Reason**: TCP stack responds to unexpected ACK with RST

#### **Filtered Port Response:**

If the port is filtered by a firewall:

- **Response Options:**
  1. **No response** (most common - firewall drops packet silently)
  2. **ICMP error message** (firewall sends rejection)
- **ICMP error types:**
  - Type 3, Code 1: Host Unreachable
  - Type 3, Code 2: Protocol Unreachable
  - Type 3, Code 3: Port Unreachable
  - Type 3, Code 9, 10, 13: Communication Administratively Prohibited
- **Interpretation**: Port is FILTERED

### 3. Scan Logic and Purpose:

#### **Primary Goal:**

- **Firewall Mapping**: Determine which ports are filtered
- **Rule Discovery**: Understand firewall rule sets
- **Network Topology**: Map filtering devices in network path

#### **State Determination:**

- **UNFILTERED**: RST packet received (port may be open or closed)
- **FILTERED**: No response or ICMP error received

#### **Important Note:**

ACK scans **cannot determine** if a port is open or closed, only whether it's filtered or unfiltered.

### 4. Firewall Detection Principles:

#### **Stateless Firewalls:**

- **Behavior**: Often block ACK packets without corresponding SYN
- **Detection**: Consistent filtering patterns
- **Rule Analysis**: Simple port-based filtering

#### **Stateful Firewalls:**

- **Behavior**: Track connection state, block unsolicited ACK packets
- **Detection**: More sophisticated filtering
- **Rule Analysis**: Connection-aware filtering

#### **No Firewall:**

- **Behavior**: All ports return RST (unfiltered)
- **Detection**: Consistent RST responses
- **Indication**: Direct host access

### 5. Advantages and Limitations:

#### **Advantages:**

- **Firewall Mapping**: Excellent for discovering filtering rules
- **Stealth**: Less suspicious than connection attempts
- **Speed**: Fast scanning (single packet per port)
- **Rule Discovery**: Reveals firewall configuration
- **Network Mapping**: Identifies filtering devices

#### **Limitations:**

- **No Open/Closed Info**: Cannot determine service availability
- **Stateful Firewall Challenges**: Modern firewalls easily detect
- **Limited Information**: Only shows filtered vs unfiltered
- **Context Dependent**: Results depend on firewall configuration
- **False Positives**: Network issues may appear as filtering

### 6. Practical Applications:

#### **Penetration Testing:**

- **Firewall Analysis**: Map firewall rules and exceptions
- **Attack Planning**: Identify potential bypass opportunities
- **Network Reconnaissance**: Understand security perimeter

#### **Security Assessment:**

- **Rule Verification**: Verify firewall rule effectiveness
- **Compliance Testing**: Ensure proper filtering implementation
- **Security Audit**: Identify configuration weaknesses

#### **Network Troubleshooting:**

- **Connectivity Issues**: Identify filtering problems
- **Rule Debugging**: Test firewall rule functionality
- **Path Analysis**: Trace filtering along network path

### 7. Detection and Countermeasures:

#### **Detection Methods:**

- **Pattern Recognition**: Multiple ACK packets to different ports
- **Timing Analysis**: Rapid scanning patterns
- **Source Analysis**: Scanning from single source IP
- **Flag Analysis**: Packets with only ACK flag set

#### **Countermeasures:**

- **Rate Limiting**: Limit response rates to scans
- **Logging**: Log and alert on scanning patterns
- **Source Blocking**: Block suspected scanning sources
- **Honeypots**: Deploy decoy services to detect scans

### 8. Packet Analysis Example:

#### **Sent ACK Packet:**

```
IP Header:
- Source: 192.168.1.100
- Destination: 192.168.1.1
- Protocol: TCP (6)

TCP Header:
- Source Port: 54321
- Destination Port: 80
- Sequence: 0x12345678
- Acknowledgment: 0x87654321
- Flags: ACK (0x10)
- Window: 1024
```

#### **Unfiltered Response (RST):**

```
IP Header:
- Source: 192.168.1.1
- Destination: 192.168.1.100
- Protocol: TCP (6)

TCP Header:
- Source Port: 80
- Destination Port: 54321
- Sequence: 0x87654321
- Acknowledgment: 0x12345679
- Flags: RST (0x04)
```

### 9. Comparison with Other Scans:

#### **ACK vs SYN Scan:**

- **Purpose**: ACK maps firewalls, SYN finds open ports
- **Information**: ACK shows filtering, SYN shows services
- **Use Case**: ACK for reconnaissance, SYN for service discovery

#### **ACK vs Stealth Scans:**

- **Detection**: ACK less stealthy than NULL/FIN/XMAS
- **Purpose**: Different goals (firewall vs service discovery)
- **Reliability**: ACK more reliable for firewall mapping

### 10. Advanced Techniques:

#### **Window Scan Variation:**

- **Method**: Analyze TCP window size in RST responses
- **Purpose**: Sometimes reveals open vs closed ports
- **Limitation**: System-dependent behavior

#### **TTL Analysis:**

- **Method**: Examine TTL values in responses
- **Purpose**: Identify filtering devices in path
- **Application**: Network topology mapping

## Summary:

ACK scans send TCP packets with only the ACK flag set to map firewall rules and determine port filtering status. They excel at firewall reconnaissance by distinguishing between filtered and unfiltered ports based on RST responses, though they cannot determine if ports are actually open or closed. This makes ACK scans invaluable for understanding network security perimeters and firewall configurations.
