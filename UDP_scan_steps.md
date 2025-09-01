# UDP Scan Steps Explanation

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
