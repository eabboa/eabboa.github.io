# Threat Hunt Report: LOLBin C2 Beaconing via BITS Jobs

**Date:** 2026-03-11 

**Analyst:** Enes Arda Baydaş

**Platform:** Elastic SIEM (Kibana) & TryHackMe

**MITRE ATT&CK:** T1197, T1105, T1071.001

````mermaid
flowchart LR
classDef input fill:#4A90D9,color:#fff
classDef process fill:#6B7280,color:#fff
classDef decision fill:#F59E0B,color:#fff
classDef output fill:#10B981,color:#fff

subgraph Detection
I1([IDS Alert Outbound HTTP])
P1[Filter Logs In Kibana]
P2[Analyze User Agent Frequency]
end

subgraph Investigation
D1{Is Activity Authorized}
O1[[Mark False Positive]]
P3[Identify bitsadmin Command Channel]
end

subgraph Containment
P4[Isolate Compromised Host]
P5[Preserve Forensic Image]
P6[Block Pastebin Domain]
end

subgraph Follow Up
O2[[Review Auth Logs]]
O3[[Investigate Initial Access]]
end

I1 --> P1
P1 --> P2
P2 --> D1
D1 -->|Yes| O1
D1 -->|No| P3
P3 --> P4
P4 --> P5
P5 --> P6
P6 --> O2
P6 --> O3

class I1 input
class P1,P2,P3,P4,P5,P6 process
class D1 decision
class O1,O2,O3 output
````

---
## Executive Summary

An IDS signature flagged anomalous outbound HTTP traffic originating from an HR workstation (192.168.x.x) Analysis of HTTP connection logs in Kibana confirmed the host used `bitsadmin.exe` (a native Windows binary) to retrieve a payload from `pastebin.com`. The attack bypasses perimeter defenses by abusing a trusted OS utility and a whitelisted public domain. Initial access vector remains unresolved and is flagged as an open investigative thread.

**Risk:** High. LOLBin-based C2 evades signature detection and AV. Pastebin's reputation prevents firewall blocking in most default configurations. Dwell time and lateral movement scope are unknown pending forensic triage.

---
## Findings

| IOC Type          | Value                            | Context                                       |
| :---------------- | :------------------------------- | :-------------------------------------------- |
| **Source IP**     | `192.168.x.x`             | Compromised HR workstation                    |
| **C2 Domain**     | `pastebin.com`                   | Legitimate service abused for payload hosting |
| **Malicious URL** | `http://pastebin.com/x.x` | Payload staging URI                           |
| **User-Agent**    | `bitsadmin`                      | LOLBin abused for outbound retrieval (T1197)  |
| **Payload**       | Extracted from Pastebin URI      | Pending sandboxed analysis                    |

---

## Detection Gap Summary

| Gap                                                    | Impact                                                              | Fix                                                                         |
| :----------------------------------------------------- | :------------------------------------------------------------------ | :-------------------------------------------------------------------------- |
| No `user_agent` anomaly alerting                       | LOLBin activity was invisible until manual hunt                     | SIEM correlation rule on non-browser user agents                            |
| `bitsadmin` executable unrestricted for standard users | Threat actor had access to a persistent, low-noise delivery tool    | AppLocker / WDAC policy                                                     |
| No outbound egress filtering on workstations           | Arbitrary C2 destinations reachable without restriction             | Outbound allowlist + proxy enforcement                                      |
| Pastebin treated as trusted in firewall config         | Payload staging on a whitelisted domain bypassed perimeter controls | Category-based blocking + TLS inspection for cloud storage / paste services |
| Initial access vector unknown                          | Remediation is containment only; reinfection risk unquantified      | Phishing log review, endpoint forensics, email gateway audit                |

---
## Detection

### Signal

IDS triggered on anomalous outbound HTTP from the HR subnet. Full packet capture was unavailable; triage was limited to HTTP connection log metadata in Kibana.
### Analysis

Standard environmental traffic (Windows Update, Google, Adobe telemetry) was filtered from the `connection_logs` index to reduce noise and surface anomalies.

<img width="1135" height="610" alt="Pasted image 20260301152109" src="https://github.com/user-attachments/assets/d4e3a5ad-9529-4231-8509-dff69faa9401" />


Frequency analysis of the `user_agent` field produced the decisive signal: `bitsadmin` appeared in 0.4% of traffic (2 log entries) against a baseline of 99.6% standard `Mozilla/5.0` variants. No administrative change request or authorized task accounted for this activity.

<img width="607" height="292" alt="Ekran görüntüsü 2026-03-01 143601" src="https://github.com/user-attachments/assets/04414b74-b546-46ac-ac85-ba415713b918" />


Filtering on `user_agent: bitsadmin` isolated two GET requests from `192.168.x.x` to pastebin.com/x.x.

<img width="1920" height="1091" alt="Pasted image 20260301152020" src="https://github.com/user-attachments/assets/d0e024f3-323b-45aa-b322-036d0be1e639" />

### Why This Matters

`bitsadmin.exe` is a signed Microsoft binary present on all Windows hosts (XP onward). Its BITS service operates asynchronously and survives reboots, making it effective for persistent, low-noise retrieval. Outbound BITS traffic is often excluded from EDR detections due to its OS-level legitimacy. Staging payloads on Pastebin exploits the domain's trusted reputation in firewall allowlists.

**MITRE ATT&CK Mapping:**

| Technique                                 | ID        | Observed Behavior                                |
| :---------------------------------------- | :-------- | :----------------------------------------------- |
| BITS Jobs                                 | T1197     | `bitsadmin` used as HTTP client for C2 retrieval |
| Ingress Tool Transfer                     | T1105     | Remote payload fetched from external staging URI |
| Application Layer Protocol: Web Protocols | T1071.001 | C2 communication over standard HTTP on port 80   |

---
## Containment & Remediation

### Immediate
1. **Isolate** `192.168.x.x` from the network segment. Prevent potential lateral movement before forensics are complete.
2. **Preserve** a full forensic image (memory + disk) of the host. Memory capture is time-critical for recovering injected payloads or BITS job queue artifacts.
3. **Review** authentication logs for user's account across all systems for the 72-hour window preceding the alert.
4. **Block** `pastebin.com` at the perimeter firewall and proxy until the incident is closed. Assess collateral impact on business operations before making the block permanent.

---
### **Note on Redacted Data**

The **Source IP** and the **Pastebin URI** were redacted in this report. These represent the solutions to specific tasks on the **TryHackMe** lab.
