### CobaltStrike and IcedID Infection: Network Traffic Analysis and C2 Identification

**Date:** 2026-03-16  

**Author:** Enes Arda Baydaş

**Category:** Network Forensics  

**Platform:** THM/Brim

**MITRE ATT&CK:** T1071.001 (Application Layer Protocol), T1105 (Ingress Tool Transfer), T1204.002 (Malicious File)  

**GRC Mapping:** NIST CSF DE.AE-2 (Analyze events to detect potential cybersecurity events), SOC 2 CC7.2 (Security incident monitoring)

---

### Executive Summary

An internal host (`10.22.5.47`) was compromised after a user executed a malicious link, leading to the download of a CobaltStrike payload (`4564.exe`) from an external staging server. 

Network analysis revealed secondary C2 communications associated with the IcedID banking trojan. 

The business risk is **Critical** due to the establishment of redundant, multi-malware C2 channels, indicating imminent risk of lateral movement, data exfiltration, or ransomware deployment.

---
````mermaid
flowchart LR

classDef input fill:#4A90D9,color:#fff

classDef process fill:#6B7280,color:#fff

classDef decision fill:#F59E0B,color:#fff

classDef output fill:#10B981,color:#fff

subgraph Infection

N1([Malicious link clicked])

N2[Download CobaltStrike payload]

N3[Connect to primary C2]

end

subgraph Detection

N4{Anomalous traffic detected}

N5[[Adversary moves laterally]]

N6[Analyze network logs]

N7[Identify secondary IcedID C2]

end

subgraph Remediation

N8{EDR telemetry present}

N9[[Isolate host and block IPs]]

N10[[Deploy EDR and TLS inspection]]

end

N1 --> N2

N2 --> N3

N3 --> N4

N4 -->|No| N5

N4 -->|Yes| N6

N6 --> N7

N7 --> N8

N8 -->|Yes| N9

N8 -->|No| N10

N10 --> N9

class N1 input

class N2,N3,N6,N7 process

class N4,N8 decision

class N5,N9,N10 output

````

### Findings

| IOC Type      | Value                                                              | Context                                   |
| ------------- | ------------------------------------------------------------------ | ----------------------------------------- |
| IPv4          | `104[.]168[.]44[.]45`                                              | Primary C2 / CobaltStrike Payload Staging |
| IPv4          | `159[.]89[.]171[.]14`                                              | Secondary C2 / IcedID Infrastructure      |
| IPv4          | `185[.]70[.]184[.]43`                                              | Secondary C2 Infrastructure               |
| Domain        | `hashingold[.]top`                                                 | Malicious DNS Query                       |
| Domain        | `ouldmakeithapp[.]top`                                             | Malicious DNS Query                       |
| File (Name)   | `4564.exe`                                                         | CobaltStrike Payload                      |
| File (SHA256) | `cbd2e49a46f4f9df1bbcd8eb7ba048692a3ddf0108aef42ff5381c3a3c572b0f` | IcedID Executable                         |

---

### Detection

**Signal** Initial network speed degradation and anomalous traffic activity from an internal endpoint prompted a review of network capture logs. Suricata intrusion detection alerts concurrently flagged events categorized as "A Network Trojan was detected" and "Potentially Bad Traffic".

**Analysis** Connection log baseline analysis identified high-frequency SSL (port 443) traffic between the internal host `10.22.5.47` and the external IP `104[.]168[.]44[.]45`. HTTP log inspection revealed a direct file download of `4564.exe` from this external IP via an unencrypted GET request (T1105). Sandbox analysis confirmed `4564.exe` as a CobaltStrike beacon. 

DNS query frequency analysis surfaced suspicious requests for `.top` top-level domains, specifically `hashingold[.]top` and `ouldmakeithapp[.]top`. OSINT correlation confirmed these domains are actively utilized in malicious campaigns (T1071.001). 

<img width="708" height="788" alt="hello" src="https://github.com/user-attachments/assets/2b81746b-0aef-44b2-b078-bfd5a71f3af8" />

<img width="900" height="936" alt="Pasted image 20260316080011" src="https://github.com/user-attachments/assets/a7265d64-18c0-4014-bddb-7a53d8d250c5" />


Pivoting to identify redundant access channels revealed the compromised host establishing secondary C2 communications with `185[.]70[.]184[.]43` and `159[.]89[.]171[.]14`. Threat intelligence integration identified a payload associated with the `159[.]89[.]171[.]14` infrastructure (`cbd2e49a...exe`) as the IcedID malware. 

<img width="705" height="380" alt="Pasted image 20260316080109" src="https://github.com/user-attachments/assets/828276c0-e45a-4020-b124-37bc436ca8e9" />
<img width="1283" height="1013" alt="Pasted image 20260316080143" src="https://github.com/user-attachments/assets/eed1e118-31c5-4df9-8f3f-19c0c1d1d61b" />
<img width="1176" height="917" alt="Pasted image 20260316080201" src="https://github.com/user-attachments/assets/c9fd6115-4683-43dc-bb43-a0bfa02e4be3" />


**Why This Technique Is Dangerous** CobaltStrike and IcedID hide communication within standard web traffic. Attackers switch between these tools to maintain a permanent foothold. Standard network security fails to detect this activity unless TLS inspection and strict DNS filtering are active.

---

### Open Threads

* **Initial Access Vector:** The specific malicious URL or phishing email the user clicked to initiate the infection chain is not present in the analyzed PCAP/logs.

* **Host-Level Execution & Lateral Movement:** Endpoint telemetry (EDR or Windows Event Logs) is required to determine what processes the CobaltStrike beacon injected into, and whether SMB (port 445) traffic observed was used for lateral movement.

---

### Containment & Remediation

**Immediate**
1. Isolate host `10.22.5.47` from the corporate network to prevent lateral movement.
2. Implement perimeter blocks (Firewall/DNS) for the identified C2 IPs (`104[.]168[.]44[.]45`, `159[.]89[.]171[.]14`, `185[.]70[.]184[.]43`) and `.top` domains.
3. Force a password reset for the user operating `10.22.5.47` and revoke any active session tokens.

**Structural Fixes**
* Restrict execution of unsigned `.exe` files downloaded from external networks.
* Implement DNS sinkholing for high-risk and newly registered Top-Level Domains (TLDs) such as `.top` and `.uno`.

---

### Detection Gap Summary

| Gap                        | Impact                                                                                                         | Recommended Fix                                                                                                        |
| -------------------------- | -------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Lack of Endpoint Telemetry | Inability to track process injection, local privilege escalation, or lateral movement attempts post-infection. | Deploy and centralize EDR telemetry or Sysmon logs (specifically Event IDs 1, 3, and 22) into the SIEM.                |
| Permissive Egress Traffic  | Allowed the unhindered download of the `4564.exe` payload over HTTP and subsequent C2 check-ins over HTTPS.    | Enforce strict egress filtering and implement TLS inspection to analyze encrypted C2 traffic for malicious signatures. |
