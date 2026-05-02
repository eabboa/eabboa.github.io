# PCAP Analysis of SSL Stripping & Credential Theft

**Date:** 2026-03-09

**Author:** Enes Arda Baydaş

**Category:** Network Forensics

**Platform:** THM / Man-in-the-Middle detection

````mermaid
flowchart LR
classDef input fill:#4A90D9,color:#fff
classDef process fill:#6B7280,color:#fff
classDef decision fill:#F59E0B,color:#fff
classDef output fill:#10B981,color:#fff

A([Alert DNS spoofing anomaly])
class A input

subgraph TrafficAnalysis
B[Filter for TLS Client Hello]
C{Is TLS handshake present}
D[Confirm SSL Strip attack]
E[Establish normal TLS baseline]
F[Filter HTTP POST traffic]
G{Are cleartext creds exposed}
end
class B,D,E,F process
class C,G decision

subgraph IncidentResponse
H[[Isolate victim endpoint]]
I[[Block rogue device MAC]]
J[[Force user password reset]]
K[[Continue network monitoring]]
end
class H,I,J,K output

subgraph NetworkHardening
L[[Enforce domain HSTS]]
M[[Enable Dynamic ARP Inspection]]
end
class L,M output

A --> B
B --> C
C -->|Yes| E
C -->|No| D
D --> F
F --> G
G -->|Yes| H
G -->|No| K
H --> I
I --> J
J --> L
L --> M
````

### 1. Executive Brief

**Scenario:** Network traffic analysis identified a Man-in-the-Middle (MitM) attack targeting the local corporate authentication portal. The attacker downgraded the victim's secure connection (HTTPS) to plain text (HTTP) and captured login credentials.

**Goal:** Triage the packet capture (PCAP), trace the protocol downgrade mechanism, and extract the exfiltrated artifacts to confirm the scope of compromise.

**Business Impact:** Stolen corporate credentials enable unauthorized access, lateral movement, and data exfiltration. Interception of employee credentials constitutes a data breach requiring immediate KVKK incident notification and isolation to mitigate operational liabilities.

### 2. The Investigation

**Trigger:** Investigation initiated following alerts of DNS spoofing linked to a rogue host (`192.168.10.55`) on the local subnet.

**Analysis:**

The attack maps to **MITRE ATT&CK T1557** (Adversary-in-the-Middle) and **T1040** (Network Sniffing).

A baseline of normal TLS communications was established by filtering for standard Client Hello packets directed at the corporate login domain.

**Wireshark Filter:** `tls.handshake.type == 1 && tls.handshake.extensions_server_name == "corp-login.acme-corp.local"`

<img width="1031" height="501" alt="Pasted image 20260307192002" src="https://github.com/user-attachments/assets/ea07ccab-6a52-49c6-9cbf-e50aff339fa7" />


**Observation:** During the attack window, the expected TLS handshake sequence ceases between the victim and the authentication server.

**Inference:** The absence of the TLS handshake, combined with known DNS spoofing activity, confirms an SSL Strip. The secure connection was intercepted and replaced with an unencrypted HTTP connection.

To locate the stolen credentials, traffic was filtered to isolate cleartext HTTP POST requests originating from the victim and directed to the attacker's IP.

**Wireshark Filter:** `http.request.method == "POST" && ip.addr == 192.168.10.55`

<img width="1026" height="255" alt="Pasted image 20260307192017" src="https://github.com/user-attachments/assets/aff55f81-e5fb-4354-881d-19e1718329ec" />


**Observation:** The victim endpoint transmitted an HTTP POST request containing user authentication variables in cleartext to the attacker's machine (`192.168.10.55`).

**Inference:** The attacker acted as a proxy, presenting the victim with an HTTP connection while maintaining an HTTPS connection to the server, stripping encryption and harvesting credentials in transit.

### 3. Indicators of Compromise (IOCs)

|**Artifact Type**|**Value**|**Context**|
|---|---|---|
|**Malicious IP**|`192.168.10.55`|Rogue host conducting DNS Spoofing and SSL Stripping.|
|**Victim IP**|`192.168.10.10`|Endpoint compromised via MitM downgrade attack.|
|**Target Domain**|`corp-login.acme-corp.local`|Internal authentication portal impersonated by the attacker.|

### 4. Behavioral Anomalies (TTPs)

- **HTTP POST over Port 80:** Credentials submitted in cleartext to a domain strictly requiring Port 443 (HTTPS).
    
- **Missing TLS Handshake:** Absence of expected `Client Hello` packets to the target domain during the authentication sequence.
    

### 5. Remediation & Hardening

**Detection Logic:**

Monitor web proxy or network logs for HTTP traffic (specifically POST requests) destined for known corporate authentication URLs that strictly utilize HTTPS. Alert on anomalous 301/302 redirects from HTTPS to HTTP for internal domains.

**Immediate Fix (Triage):**

1. Isolate the victim endpoint (`192.168.10.10`) from the network via EDR or switchport shutdown.
    
2. Block the rogue device (`192.168.10.55`) MAC address at the local access switch to halt interception.
    
3. Force a global password reset for the compromised user account and invalidate active session tokens.
    

**Root Cause Fix (Mitigation):**

1. **HSTS Implementation:** Enforce HTTP Strict Transport Security (HSTS) on `corp-login.acme-corp.local` and preload the domain. This forces browsers to reject unencrypted connections, neutralizing downgrade attacks.
    
2. **Network Hardening:** Enable Dynamic ARP Inspection (DAI) and DHCP Snooping on local switches to prevent rogue IPs from intercepting subnet traffic.
