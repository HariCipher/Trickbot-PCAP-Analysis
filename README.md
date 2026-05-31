# TrickBot Infection — Network Traffic Analysis

**PCAP source:** malware-traffic-analysis.net — 2017-09-18  
**Tool:** Wireshark  
**Malware family:** TrickBot  
**Analyst:** Harilal P

## Summery

THis Project Analyzes a publicaly available 2017 TrickBot infection Pcap captured in Wireshark. The PCAP was obtained from Malware Traffic Analysis and contains traffic associated with a TrickBot infection, including reconnaissance activity, malicious payload delivery, DNS lookups, and encrypted external communications. The objective of the analysis was to identify the infected host, extract indicators of compromise (IOCs), investigate suspicious network behavior, and understand the infection chain using only network traffic artifacts.

## Key Findings

- Infected host identified as **10.9.18.105** via endpoint statistics
- The ipinfo.io/ip request suggests the infected host was checking its public IP address before external communications.
- The file kassa2g20.png appeared to be an image but was actually a Windows executable disguised as a PNG file.
- DNS analysis showed 6-express.ch resolving to 77.236.96.52, which was later used for the suspicious file download.
- The host communicated with 194.87.232.127 over encrypted TLS on port 447/TCP, indicating possible TrickBot C2 activity.
- No HTTP POST observed — exfiltration likely occurred over encrypted channel

## Indicators of Compromise

| Type | Value | Context |
|------|-------|---------|
| Infected host IP | 10.9.18.105 | Highest traffic internal host |
| C2 IP | 194.87.232.127 | TLS port 447 communications |
| Delivery server IP | 77.236.96.52 | Resolved from 6-express.ch |
| C2 domain | 6-express.ch | Hosted malicious payload |
| Recon domain | ipinfo.io | Public IP discovery |
| Malicious file | kassa2g20.png | PE executable disguised as PNG |
| C2 port | 447/TCP | Non-standard, TrickBot-specific |

## Attack Flow

```text
Infected Host (10.9.18.105)
            │
            ▼
Public IP Reconnaissance
(ipinfo.io/ip)
            │
            ▼
DNS Resolution
6-express.ch → 77.236.96.52
            │
            ▼
HTTP GET Request
/kassa2g20.png
            │
            ▼
PE Executable Downloaded
(Disguised as PNG)
            │
            ▼
Payload Delivered
            │
            ▼
Encrypted TLS Communication
194.87.232.127:447
            │
            ▼
Potential TrickBot C2 Activity
```

## MITRE ATT&CK Mapping

| Technique | ID | Observed |
|-----------|----|---------|
| Non-Standard Port | T1571 | C2 over TCP 447 |
| Encrypted Channel | T1573 | TLS C2 traffic |
| Masquerading | T1036.005 | PE disguised as PNG |
| Gather Victim Network Info | T1590 | ipinfo.io recon |
| Ingress Tool Transfer | T1105 | Payload download |

## Screenshots

| Screenshot | Description                                        |
| ---------- | -------------------------------------------------- |
| **Protocol_Hierarchy.png**  | Protocol breakdown observed in the PCAP.           |
| **Victim_Host_Identification.png**  | Identification of the infected host (10.9.18.105). |
| **Public_IP_Reconnaissance.png**  | Public IP reconnaissance using `ipinfo.io`.        |
| **Malware_Payload_Disguised_As_PNG.png**  | Fake PNG file revealed as a PE executable.         |
| **TLS_C2_Communication_Port447.png**  | TLS communication over port 447/TCP.               |
| **TCP_Conversation_Summary.png**  | Summary of key TCP conversations.                  |
| **DNS_Query_6Express.png**  | DNS resolution for `6-express.ch`.                 |
| **DNS_Query_IPInfo.png**  | DNS resolution for `ipinfo.io`.                    |

## Analysis Notes

* The most surprising finding was that a file named `kassa2g20.png` turned out to be a Windows executable, showing how malware can disguise payloads as harmless files.
* No HTTP POST requests were observed in the capture. However, this does not rule out data exfiltration, as traffic may have been sent through encrypted TLS channels or outside the captured timeframe.
* In a real incident, the next step would be to investigate the downloaded executable and analyze the host for signs of compromise and persistence.

## References

- [malware-traffic-analysis.net — 2017-09-18](https://www.malware-traffic-analysis.net/2017/09/18/index.html)
- MITRE ATT&CK: https://attack.mitre.org
- Full analysis walkthrough: [analysis.md](analysis.md)
