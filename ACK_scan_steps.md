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
