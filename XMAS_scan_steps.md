# XMAS Scan Steps Explanation

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
