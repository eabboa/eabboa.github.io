### SIEM Hunting: Identifying BITSAdmin LOLBin C2 Traffic in Kibana

**Date:** 2026-03-23

**Author:** Enes Arda Baydaş

**Domain:** SIEM Hunting / SOC Triage  

**Environment:** TryHackMe (ItsyBitsy)  

**MITRE ATT&CK:** T1197 (BITS Jobs), T1105 (Ingress Tool Transfer), T1071.001 (Application Layer Protocol: Web Protocols)  

---

### Executive Summary

During routine SOC monitoring, a suspicious C2 connection was detected originating from an HR user's workstation. Subsequent log analysis via Kibana identified that the attacker leveraged the `bitsadmin` LOLBin to bypass traditional egress controls and retrieve a malicious payload from a public file-sharing site. 

**Risk Rating: High** 
The use of native Windows binaries for C2 retrieval indicates active defense evasion and successful arbitrary code execution capabilities on the endpoint.

---

````mermaid
flowchart LR

classDef input fill:#4A90D9,color:#fff

classDef process fill:#6B7280,color:#fff

classDef decision fill:#F59E0B,color:#fff

classDef output fill:#10B981,color:#fff

subgraph Triage

A([IDS Alert Triggered])

B[Ingest Logs to Kibana]

C[Filter Trusted Domains]

D{Anomalous Connection}

end

subgraph Analysis

E[Analyze User Agent]

F{Is BITSAdmin Used}

G[Investigate Other Tools]

H[Identify Payload Server]

end

subgraph Response

I[[Continue Monitoring]]

J[[Isolate Host and Block]]

end

A --> B

B --> C

C --> D

D -->|No| I

D -->|Yes| E

E --> F

F -->|No| G

F -->|Yes| H

H --> J

class A input

class B,C,E,G,H process

class D,F decision

class I,J output
````

---
### Key Artifacts & Signatures

| Type (IOC / Artifact)    | Value / Location            | Context & Significance                                                                      |
| ------------------------ | --------------------------- | ------------------------------------------------------------------------------------------- |
| **Compromised Host IP**  | `192.166.65.54`             | The internal IP address of the suspected HR user (Browne).                                  |
| **C2 Domain**            | `pastebin.com`              | A well-known file-sharing site acting as the C2 server for malicious communication.         |
| **C2 URI**               | `/yTg0Ah6a`                 | The specific URI path hosting the payload.                                                  |
| **Target File**          | `secret.txt`                | The file accessed on the file-sharing site, which contained the lab flag `THM{...}`.        |
| **User-Agent Signature** | `bitsadmin` (Version `3.2`) | The network signature identifying the built-in Windows binary used to execute the download. |

---

### Defense Posture Summary

| Gap / Capability                         | Impact                                                                                                                    | Recommended Action / Result                                                                                                             |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| **Capability:** Centralized HTTP Logging | Ingestion of proxy/HTTP connection logs into the Kibana `connection_logs` index allowed for retrospective threat hunting. | **Result:** Enabled successful identification of the C2 channel and execution tool.                                                     |
| **Gap:** Application Control Evasion     | Security software implicitly trusted signed Microsoft executables, allowing BITSAdmin to bypass execution policies.       | **Recommended:** Restrict BITSAdmin execution to authorized administrative accounts and block anomalous User-Agents at the proxy level. |

---

### Technical Analysis

**Trigger / Hypothesis** An alert triggered on the IDS solution indicating potential C2 communication from user Browne in the HR department. Due to resource constraints, a week's worth of HTTP connection logs were ingested into a Kibana index (`connection_logs`) to investigate the anomaly and identify the malicious payload.

**Analytical Execution** Triage began by filtering the `connection_logs` index to exclude noisy, trusted domains (e.g., `*windows*`, `*microsoft*`, `*google*`, `*adobe*`). This data reduction technique isolated anomalous HTTP requests, revealing an active connection to `pastebin.com` originating from the internal IP `192.166.65.54`. 

Initial hypothesis suggested searching for specific payload file extensions (e.g., `.bin`). However, threat actors rarely name payloads with explicit binary extensions, often opting for `.txt` or no extension to evade signature-based detection. Pivoting the forensic focus from the *payload extension* to the *executing process signature* involved analyzing the `user_agent` field.  This revealed that the requests to the C2 URL `pastebin.com/yTg0Ah6a` were initiated by `bitsadmin` (Version 3.2), targeting a file named `secret.txt`. 

**Threat Mechanics** The adversary utilized BITSAdmin (Background Intelligent Transfer Service), a legitimate, digitally signed Windows binary (LOLBin). Attackers favor BITS because it is designed to download updates asynchronously in the background, rendering its network traffic difficult to distinguish from legitimate system updates. By using built-in tools, the attacker avoids dropping custom malware to disk, effectively bypassing signature-based endpoint controls. In network telemetry, the executable does not appear directly; rather, its presence is verified via the User-Agent string it presents during HTTP communication.

---

### Open Threads & Limitations
- **Initial Access:** The logs provided do not contain the initial vector (e.g., phishing payload, exploited vulnerability) that allowed the attacker to invoke the BITSAdmin command on the endpoint.
- **Post-Exploitation Scope:** Analysis is limited strictly to HTTP connection logs; endpoint execution logs (e.g., Sysmon Event ID 1) are required to determine what actions the payload performed upon execution.

---

### Remediation & Hardening

**Immediate Response** 
1. Isolate endpoint `192.166.65.54` from the corporate network to prevent further C2 communication or lateral movement.
2. Block egress HTTP/HTTPS traffic to `pastebin.com/yTg0Ah6a` at the perimeter firewall/proxy.

**Structural Engineering** 
* **Detection Logic:** Deploy SIEM rules to trigger high-severity alerts for network traffic containing the `bitsadmin` or `Microsoft BITS` User-Agent string when communicating with non-Microsoft, external IP addresses or known public file-sharing domains.
* **Endpoint Hardening:** Implement Group Policy Objects (GPOs) or AppLocker rules to restrict the execution of `bitsadmin.exe` strictly to authorized system processes and administrative accounts, enforcing the principle of least privilege.

Sigma rule for this scenario:

````
title: Suspicious BITSAdmin Payload Retrieval (Network)
id: 9a2b53c1-4f8d-4a12-8e2c-3b9a7f8e1d2c
status: experimental
description: Detects HTTP/HTTPS requests where the User-Agent indicates BITSAdmin usage, but the destination domain is not a known Microsoft update server. This is highly indicative of Living off the Land (LOLBin) payload retrieval or C2 communication.
author: Enes Arda Baydaş
date: 2026-03-20
logsource:
    category: proxy
    # If mapping directly to the Kibana index from the lab, 
    # category could be mapped to 'connection_logs'
detection:
    selection_ua:
        c-useragent|contains:
            - 'bitsadmin'
            - 'Microsoft BITS'
    selection_method:
        cs-method:
            - 'GET'
            - 'HEAD'
    filter_trusted_domains:
        cs-host|contains:
            - 'microsoft.com'
            - 'windowsupdate.com'
            - 'msedge.net'
            - 'google.com'
            - 'gvt1.com'
            - 'adobe.com'
    condition: selection_ua and selection_method and not filter_trusted_domains
falsepositives:
    - Third-party software or legitimate internal scripts utilizing BITS for application updates from vendor domains.
level: high
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1197
    - attack.t1105
    - attack.t1071.001
````

---

