# Network Miner PCAP Analysis Guide

**Version:** 1.1  
**Last Updated:** 2026-02-19  
**Classification:** Internal Use

---

## Network Miner Overview

Network Miner is a network forensic analysis tool that extracts artifacts from PCAP files without requiring deep packet inspection.

---

## Artifact Extraction

```
PCAP File Analysis:

Network Miner automatically extracts:
├─ Files: Downloaded files from traffic
├─ Images: Images viewed in browsers
├─ Domains: All DNS queries
├─ Hosts: All IP addresses in traffic
├─ Credentials: FTP/HTTP credentials
└─ Operating Systems: Based on TTL, TCP window size

EXAMPLE: Malware Download Detection

PCAP: incident_2026_02_19.pcap

Extracted Artifacts:
├─ Downloaded file: invoice.exe (512 KB)
│  ├─ MD5: a1b2c3d4e5f6g7h8
│  ├─ VirusTotal: 45/70 engines detect malware
│  └─ Verdict: EMOTET BANKER
│
├─ DNS Queries:
│  ├─ malware-download.xyz (resolved to 203.0.113.42)
│  └─ Verdict: Known attacker domain
│
├─ Hosts:
│  ├─ 10.0.20.33 (victim workstation)
│  ├─ 203.0.113.42 (attacker C2 server)
│  └─ 8.8.8.8 (Google DNS)
│
└─ Timeline: 2026-02-19 14:22 UTC
```

---

## References

- Network Miner Official Documentation
- PCAP Analysis Guide
- Wireshark Integration

---

*Document Maintenance:*
- Update tools as new versions released
- Document common extraction patterns
- Build library of analysis examples