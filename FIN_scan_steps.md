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
