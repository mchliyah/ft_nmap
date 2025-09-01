# NULL Scan Steps Explanation

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
