# Wireshark Network Traffic Analysis Guide

**Version:** 1.6  
**Last Updated:** 2026-02-19  
**Classification:** Internal Use

---

## Wireshark Fundamentals

Wireshark is a network packet analyzer that captures and displays network traffic in real-time. Essential for SOC analysts investigating network-based incidents.

---

## Packet Capture Basics

### Capture Setup

```
Wireshark Capture Options:

1. Choose Interface
   ├─ Ethernet0 (main network)
   ├─ WiFi0 (wireless)
   └─ VPN (encrypted tunnel)

2. Set Capture Filter (before capture)
   ├─ Capture only traffic of interest
   ├─ Reduces file size and processing
   └─ Example: "tcp port 443" (HTTPS only)

3. Configure Display Filter (after capture)
   ├─ Filter what you see (doesn't affect capture)
   ├─ Dynamic (change while analyzing)
   └─ Example: "ip.addr == 203.0.113.42" (single IP)

4. Capture File Options
   ├─ Rotating files (prevent huge single file)
   ├─ Ring buffer (keep only recent packets)
   └─ Compression (save disk space)
```

### Packet Anatomy

```
OSI Model → Packet Structure:

┌─ Layer 7 (Application):   [HTTP/SMTP/DNS data]
├─ Layer 6 (Presentation):  [Encryption/compression]
├─ Layer 5 (Session):       [Session establishment]
├─ Layer 4 (Transport):     [TCP/UDP header]
├─ Layer 3 (Network):       [IP header]
├─ Layer 2 (Data Link):     [Ethernet header]
└─ Layer 1 (Physical):      [Raw bits on wire]

Example TCP/IP Packet:

[Ethernet Header (14 bytes)]
├─ Destination MAC: aa:bb:cc:dd:ee:ff
├─ Source MAC: 11:22:33:44:55:66
└─ Type: IPv4 (0x0800)

[IP Header (20 bytes minimum)]
├─ Version/IHL: 4/5
├─ TTL: 64
├─ Protocol: TCP (6)
├─ Source IP: 10.0.20.33
└─ Destination IP: 203.0.113.42

[TCP Header (20 bytes minimum)]
├─ Source Port: 52341
├─ Destination Port: 443
├─ Flags: SYN (connection initiation)
└─ Window Size: 65535

[Application Data]
└─ HTTPS TLS handshake / encrypted payload
```

---

## Common Wireshark Display Filters

### Basic Filters

```
IP-based filtering:
├─ ip.addr == 192.168.1.1              → Single IP
├─ ip.src == 10.0.0.0/8                → Source IP range
├─ ip.dst == 203.0.113.42              → Destination IP
├─ ip.addr != 192.168.1.1              → Exclude IP
└─ ip.ttl < 10                         → Low TTL (suspicious)

Port-based filtering:
├─ tcp.port == 443                     → HTTPS only
├─ tcp.srcport == 22                   → SSH source port
├─ udp.dstport == 53                   → DNS destination
├─ tcp.flags.syn == 1                  → SYN packets (connections)
└─ tcp.window_size == 0                → Zero window (reset)

Protocol-specific:
├─ http                                → HTTP traffic only
├─ dns                                 → DNS queries
├─ smtp                                → Email
├─ ssh                                 → Secure shell
├─ tls                                 → Encrypted (HTTPS/TLS)
└─ ssl || tls                          → Both SSL and TLS
```

### Advanced Filters

```
Complex conditions:
├─ (ip.addr == 10.0.0.0/8) && (tcp.port == 443)
│  → Traffic from 10.0.0.0/8 to port 443
│
├─ (tcp.flags.syn == 1) && (tcp.flags.ack == 0)
│  → SYN packets (connection initiation, not acknowledgment)
│
├─ tcp.stream eq 5
│  → Only packets from TCP stream #5
│
├─ frame.time_relative > 10 && frame.time_relative < 20
│  → Packets between 10-20 seconds into capture
│
└─ data contains "Administrator"
   → Frames containing string "Administrator"
```

---

## Real-World Analysis Scenarios

### Scenario 1: Investigating C2 Communication

```
INCIDENT: System suspected of beaconing to C2 server

Analysis Steps:

1. Identify suspect system:
   ├─ Filter: ip.src == 10.0.20.33
   ├─ Result: 47 packets in 15 seconds
   └─ Observation: Unusual outbound connections

2. Identify destination:
   ├─ Filter: ip.src == 10.0.20.33
   ├─ Right-click packet → "Resolve name"
   ├─ IP: 203.0.113.42 (resolves to AS25 Rostelecom, Russia)
   └─ Observation: Non-business destination

3. Examine packet pattern (beaconing):
   ├─ Wireshark → Statistics → Conversations
   ├─ Shows: 10.0.20.33 ↔ 203.0.113.42
   │  ├─ Packets: 50 (25 each direction)
   │  ├─ Bytes: 51 KB
   │  └─ Duration: 14 minutes 32 seconds
   ├─ Interval analysis:
   │  ├─ Packet 1: 09:00:00
   │  ├─ Packet 2: 09:01:00 (60 seconds later)
   │  ├─ Packet 3: 09:02:00 (60 seconds later)
   │  └─ Pattern: Perfect 60-second intervals (beaconing!)

4. Examine traffic content:
   ├─ Right-click packet → "Follow → TCP Stream"
   ├─ Display: Raw binary data (encrypted HTTPS)
   ├─ Data size: Consistent 512-1024 bytes per beacon
   ├─ Observation: Consistent packet size = malware signature
   │  (Normal traffic varies based on content)
   └─ Export to file for hex analysis

5. Determine C2 infrastructure:
   ├─ DNS resolution check:
   │  ├─ Filter: dns && ip.dst == 203.0.113.42
   │  ├─ Result: No DNS for this IP (hardcoded)
   │  └─ Observation: Attacker using IP directly
   ├─ WHOIS lookup: 203.0.113.42
   │  ├─ Owner: Kremlin-linked ISP
   │  └─ Observation: Possibly state-sponsored
   ├─ Certificate check (HTTPS):
   │  ├─ Filter: tls && ip.addr == 203.0.113.42
   │  ├─ Certificate: *.cdn.microsoft.com (SPOOFED SNI!)
   │  └─ Observation: Attacker disguising C2 as Microsoft

6. Evidence preservation:
   ├─ Export full PCAP file
   ├─ Document timeline (first beacon: 09:00:00)
   ├─ Screenshot Wireshark statistics
   └─ Archive for forensics/law enforcement

FINDINGS:
├─ System 10.0.20.33 compromised (Emotet botnet)
├─ C2 server: 203.0.113.42 (Russia)
├─ Infection time: Started ~09:00 UTC today
├─ Data exfiltration: Minimal (512 bytes = check-in only)
└─ Severity: CRITICAL - immediate isolation required

RESPONSE:
├─ Isolate 10.0.20.33 from network
├─ Block 203.0.113.42 at firewall
├─ Collect forensic image before rebuild
└─ Activate incident response
```

### Scenario 2: Detecting Data Exfiltration

```
INCIDENT: Large data transfer detected by DLP

Analysis Steps:

1. Identify exfiltration direction:
   ├─ Filter: ip.src == 10.0.50.15 (suspected source)
   ├─ Statistics → Endpoints
   ├─ Identify destination with high bytes:
   │  ├─ 10.0.50.15 → 203.0.113.99 (external)
   │  │  ├─ Bytes sent: 2.3 GB
   │  │  └─ Duration: 8 hours
   │  └─ Observation: Large outbound transfer to external IP

2. Analyze traffic pattern:
   ├─ Right-click conversation → "Apply as filter"
   ├─ Filter: ip.addr == 10.0.50.15 && ip.addr == 203.0.113.99
   ├─ Observation: HTTP over port 443 (encrypted)
   ├─ Bytes per packet: 1400-1500 (normal MTU)
   └─ Conclusion: Data streaming (not typical C2 beacon)

3. Identify what was exfiltrated:
   ├─ Filter: http
   ├─ Look for HTTP GET/POST requests
   ├─ Example: POST /upload HTTP/1.1
   │  ├─ Content-Type: application/x-www-form-urlencoded
   │  ├─ Content-Length: 2,300,000,000 (2.3 GB!)
   │  └─ Data: Binary (likely ZIP or encrypted)
   ├─ Unable to see clear text (encrypted HTTPS)
   └─ Conclusion: Large encrypted file transferred

4. Timeline analysis:
   ├─ Filter: frame.time_relative
   ├─ Start: 09:30 (when DLP alert triggered)
   ├─ End: 17:00 (8 hours of steady transfer)
   ├─ Rate: 2.3 GB / 8 hours = 287.5 MB/hour = 80 KB/sec
   └─ Observation: Sustainable data exfiltration rate

5. Protocol analysis:
   ├─ Protocol used: HTTPS (port 443)
   ├─ TLS version: 1.2 (standard)
   ├─ Cipher: AES-256-GCM (strong)
   ├─ Certificate: Self-signed (RED FLAG!)
   └─ Observation: Likely attacker-controlled server

6. Destination analysis:
   ├─ WHOIS: 203.0.113.99
   │  ├─ Owner: Bulletproof hosting provider
   │  ├─ Located: Netherlands
   │  └─ Reputation: Known for hosting malware
   ├─ Reverse DNS: None (anonymous)
   └─ Observation: Deliberately anonymous infrastructure

EVIDENCE OF EXFILTRATION:
├─ Data transferred: 2.3 GB (likely customer/financial data)
├─ Duration: 8 hours (deliberate, not accident)
├─ Encryption: Custom (not standard HTTPS)
├─ Destination: Criminal infrastructure (bulletproof)
├─ Timing: Business hours (attacker present)
└─ Severity: CRITICAL - data breach confirmed

INVESTIGATION QUESTIONS:
├─ What system did this originate from? (10.0.50.15)
├─ What data was exfiltrated? (Need file forensics)
├─ How long has attacker had access? (Check logs)
├─ How many other systems compromised? (Hunt in SIEM)
└─ What was the attack vector? (Initial compromise)

IMMEDIATE ACTIONS:
├─ Block 203.0.113.99 at firewall
├─ Isolate 10.0.50.15 from network
├─ Begin forensic image collection
├─ Search SIEM for related activity
├─ Notify legal/compliance (data breach notification)
└─ Activate incident response procedures
```

### Scenario 3: Analyzing Network Reconnaissance

```
INCIDENT: Multiple ports scanned from external IP

Analysis Steps:

1. Identify scanning activity:
   ├─ Filter: tcp.flags.syn == 1 && !tcp.flags.ack
   │  (SYN without ACK = connection initiation)
   ├─ Statistics → Endpoints
   ├─ Identify source IP with many destinations:
   │  ├─ 203.0.113.100 (attacker scanning)
   │  ├─ Attempting connections to: 50+ different ports
   │  └─ Observation: Port scanning activity detected

2. Analyze scan pattern:
   ├─ Filter: ip.src == 203.0.113.100
   ├─ Right-click → "Follow → TCP Stream"
   ├─ Timeline of attempts:
   │  ├─ 09:00:00 → Port 22 (SSH) - RST (rejected)
   │  ├─ 09:00:01 → Port 23 (Telnet) - RST
   │  ├─ 09:00:02 → Port 25 (SMTP) - RST
   │  ├─ 09:00:03 → Port 80 (HTTP) - SYN-ACK (OPEN!)
   │  ├─ 09:00:04 → Port 443 (HTTPS) - SYN-ACK (OPEN!)
   │  └─ 09:00:05 → Port 3389 (RDP) - RST
   ├─ Speed: One port per second (methodical scanning)
   └─ Pattern: Systematic port enumeration

3. Identify open services:
   ├─ Ports responding with SYN-ACK:
   │  ├─ Port 80 (HTTP) - Web server
   │  ├─ Port 443 (HTTPS) - Web server
   │  └─ Closed ports (RST): 22, 23, 25, 3389, 8080, etc.
   ├─ Conclusion: Only web server exposed
   └─ Risk assessment: Limited exposure (only web ports)

4. Identify vulnerabilities being probed:
   ├─ Filter: http && ip.src == 203.0.113.100
   ├─ HTTP requests to web server:
   │  ├─ GET /admin (probing for admin panel)
   │  ├─ GET /wp-admin (probing for WordPress)
   │  ├─ GET /.git/config (probing for exposed Git)
   │  ├─ GET /web.config (probing for IIS config)
   │  └─ GET /backup.sql (probing for database backup)
   ├─ Observation: Attacker searching for common weaknesses
   └─ Conclusion: Vulnerability enumeration

5. Timeline and methodology:
   ├─ Duration: 45 minutes (09:00 - 09:45)
   ├─ Scope: Single source IP
   ├─ Methodology: Methodical, not random (likely automated)
   ├─ Timing: 09:00 UTC (business hours, attacker working)
   └─ Observation: Professional reconnaissance

ANALYSIS FINDINGS:
├─ Attacker IP: 203.0.113.100 (Russian ISP - threat intel match)
├─ Activity: Port scanning + Web vulnerability enumeration
├─ Success rate: Found 2 open ports (80, 443)
├─ Exploitable vulnerabilities: To be determined by next phase
└─ Threat level: Active reconnaissance = precursor to attack

NEXT STEPS:
├─ Monitor web server logs for exploitation attempts
├─ Check if web apps have known vulnerabilities
├─ Block scanning IP at firewall (optional, allows monitoring)
├─ Harden web server (disable unnecessary features)
├─ Monitor for follow-up exploitation attempts
└─ Escalate if actual exploitation occurs
```

---

## Advanced Wireshark Features

### I/O Graphs

```
Visualize traffic patterns over time:

Menu → Statistics → I/O Graphs

Shows:
├─ Traffic volume (packets/second)
├─ Bandwidth usage (bits/second)
├─ Packet count over time (detect anomalies)
└─ Identify patterns (beaconing = regular spikes)

Use cases:
├─ Detect beaconing (regular interval spikes)
├─ Identify DDoS attacks (massive traffic spike)
├─ Monitor data exfiltration (sustained high bandwidth)
└─ Correlate with other alerts (timing analysis)
```

### Protocol Hierarchy

```
Menu → Statistics → Protocol Hierarchy

Shows:
├─ All protocols in capture
├─ Byte count per protocol
├─ Percentage of total traffic
└─ Identify dominant traffic types

Example output:
├─ TCP: 75% (business app traffic)
├─ UDP: 15% (DNS, NTP)
├─ ICMP: 5% (ping traffic)
├─ ARP: 5% (network discovery)
└─ Interpretation: Normal office environment
```

### Following Streams

```
Export full TCP/UDP stream:

Right-click packet → Follow → TCP Stream
Shows:
├─ Complete conversation (both directions)
├─ Raw data (hexadecimal)
├─ Interpreted ASCII
└─ Save to file for analysis

Use cases:
├─ Analyze HTTP request/response
├─ Extract credentials (if unencrypted!)
├─ Analyze application-layer attack
└─ Preserve evidence for investigation
```

---

## Wireshark Display Filter Cheat Sheet

```
Common Investigation Filters:

FINDING COMPROMISE:
├─ tcp.port == 4444  → Check for Metasploit default port
├─ tcp.port == 5555  → Malware beaconing
├─ dns.qry.name contains "c2"
├─ ip.ttl < 10
└─ (Unusual values indicate non-standard traffic)

FINDING LATERAL MOVEMENT:
├─ tcp.dstport == 445  → SMB (file share access)
├─ tcp.dstport == 3389 → RDP (remote desktop)
├─ tcp.dstport == 135  → RPC (remote proc call)
└─ All between internal IPs

FINDING DATA THEFT:
├─ (data.len > 10000000)  → Large data transfers
├─ (tcp.len > 1000) && (tcp.flags.psh)
│  → Large packets with data (not just headers)
├─ http.request.method == POST && http.content_length > 1000000
│  → Large POST uploads
└─ Destination: External IPs

FINDING SCANNING:
├─ tcp.flags.syn == 1 && !tcp.flags.ack
│  → SYN packets (connection initiation)
├─ tcp.flags.fin == 1 && !tcp.flags.ack
│  → FIN packets (connection termination)
└─ Multiple to different ports/IPs = scanning
```

---

## References

- Wireshark Official Documentation
- SANS Network Analysis Guide
- TCP/IP Illustrated

---

*Document Maintenance:*
- Review common filters quarterly
- Add new filters as new threats emerge
- Update protocols based on network changes
