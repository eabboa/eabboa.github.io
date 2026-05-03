### DFIR: Tracking Phishing, Local Enumeration, and DNS Tunneling Exfiltration

**Date:** 2026-04-01  

**Author:** Enes Arda Baydaş

**Domain:** Incident Response  
 
**Environment:** TryHackMe (Boogeyman 1)  

**MITRE ATT&CK:** T1566.001 (Spearphishing Attachment), T1059.001 (PowerShell), T1082 (System Information Discovery), T1005 (Data from Local System), T1048.003 (Exfiltration Over Alternative Protocol - Unencrypted Channel)  

---

````mermaid
flowchart LR
    classDef input fill:#4A90D9,color:#fff
    classDef process fill:#6B7280,color:#fff
    classDef decision fill:#F59E0B,color:#fff
    classDef output fill:#10B981,color:#fff

    subgraph Initial Access
        id1([Email Received]):::input --> id2[Extract LNK File]:::process
    end

    subgraph Execution & Discovery
        id2 --> id3[Execute PowerShell]:::process
        id3 --> id4[Download Seatbelt & sq3]:::process
        id4 --> id5{Query SQLite?}:::decision
        id5 -->|Yes| id6[Read Sticky Notes]:::process
        id5 -->|No| id7[Further Enumeration]:::process
    end

    subgraph Exfiltration
        id6 --> id8[Locate KeePass DB]:::process
        id8 --> id9[Hex Encode Payload]:::process
        id9 --> id10[[DNS Tunnel Exfil]]:::output
    end
````

### Executive Summary

The analysis of a phishing incident revealed that a threat actor compromised a workstation by opening a malicious LNK file disguised as an invoice. The attacker utilized PowerShell for local enumeration and payload staging, ultimately harvesting Microsoft Sticky Notes databases and exfiltrating a KeePass password database (`protected_data.kdbx`). Data exfiltration was achieved via DNS tunneling using hex-encoded subdomains, bypassing standard outbound network filtering. 

**Risk rating:** Critical. Sensitive credential stores and a master password were successfully exfiltrated to an attacker-controlled infrastructure.

---

### Key Artifacts & Signatures

| Type (IOC / Artifact / Query) | Value / Location | Context & Significance |
|-------------------------------|------------------|------------------------|
| **C2 Domain** | `files[.]bpakcaging[.]xyz` | File hosting server used to stage the initial payload and enumeration tools. |
| **C2 Domain** | `cdn[.]bpakcaging[.]xyz` | Secondary command and control channel used for POST requests. |
| **Payload** | `Invoice_20230103.lnk` | Initial access payload delivered via an encrypted ZIP archive. |
| **Forensic Artifact** | `plum.sqlite` | Microsoft Sticky Notes database targeted by the attacker to locate credential data. |
| **Exfiltrated Data** | `protected_data.kdbx` | KeePass database containing sensitive passwords exfiltrated via DNS tunneling. |

---

### Defense Posture Summary

| Gap / Capability | Impact | Recommended Action / Result |
|------------------|--------|-----------------------------|
| **Email Filtering** | Failed: Phishing email delivered with malicious LNK inside an encrypted ZIP. | Implement strict LNK blocking and quarantine encrypted archives from external senders. |
| **Endpoint Execution** | Failed: PowerShell successfully executed base64 payloads and downloaded LotL binaries. | Restrict PowerShell execution policy and enable Constrained Language Mode for non-admin users. |
| **Network Egress** | Failed: DNS tunneling bypassed proxy controls. | Implement DNS query length monitoring and restrict external DNS resolution to approved corporate servers. |

---

### Technical Analysis & Narrative

**Trigger / Hypothesis** An investigation was initiated following the receipt of a suspicious email claiming an overdue invoice payment. The goal was to trace the execution chain, identify the attacker's actions on the endpoint, and determine the extent of data compromise.

**Analytical Execution** The initial vector was an email containing an encrypted attachment, `Invoice.zip`. Extracting the archive revealed `Invoice_20230103.lnk`, which executed a base64-encoded PowerShell payload to download the next stage from `hxxp[://]files[.]bpakcaging[.]xyz/update` (T1566.001, T1059.001). 

<img width="1588" height="888" alt="Pasted image 20260307142330" src="https://github.com/user-attachments/assets/83a61cf2-c3a7-4928-826f-e4c9238d0802" />

Log analysis of `powershell.json` via `jq` parsing of `ScriptBlockText` events uncovered the attacker's local enumeration activities. The threat actor downloaded `Seatbelt.exe` (`sb.exe`) for system profiling and `sq3.exe` to query local SQLite databases (T1082). Specifically, the attacker targeted `plum.sqlite` (Microsoft Sticky Notes) to extract credentials, leading them to locate `protected_data.kdbx` (T1005). To bypass standard egress filters, the attacker hex-encoded the KeePass database and exfiltrated it in chunks via `nslookup` A-record queries to `bpakcaging.xyz` (T1048.003). 

<img width="1465" height="176" alt="Pasted image 20260307142541" src="https://github.com/user-attachments/assets/e6e49f76-051b-47d0-8175-6c26eb1795da" />

PCAP analysis of HTTP and TCP streams (specifically stream 750) revealed the attacker's secondary C2 communications. Parsing the URL-encoded POST request data identified the compromised KeePass Master Password in plaintext. 

<img width="1893" height="767" alt="Pasted image 20260307153528" src="https://github.com/user-attachments/assets/4825443a-5b57-46e5-8811-5e1c287fa093" />
<img width="975" height="870" alt="Pasted image 20260307153612" src="https://github.com/user-attachments/assets/bbdaa5c4-d884-4c69-839f-c2f05fa854c7" />
(Master password here is a dummy password for the THM lab.)

**Threat Mechanics** The threat actor leveraged Protocol Conformance to evade detection during exfiltration. By converting the binary KeePass database into hex strings, the payload complied with the LDH (Letters, Digits, Hyphens) rule of RFC 1035 for DNS labels. This allowed the attacker to tunnel the data through recursive DNS resolvers via `nslookup`, a Living-off-the-Land (LotL) binary, effectively bypassing HTTP/S proxy logs and firewalls that do not inspect DNS query syntax.

---

### Open Threads & Limitations
None — operation fully concluded. The attack chain was traced from initial access through to the exact contents of the exfiltrated data and the compromised master password.

---

### Remediation & Hardening

**Immediate Response**
1. Isolate the compromised workstation from the corporate network to prevent further lateral movement or data exfiltration.
2. Reset the compromised KeePass Master Password (`%p9^3!IL^Mz47E2GaT^y`) and immediately rotate all credentials stored within the `protected_data.kdbx` vault.
3. Block the `*.bpakcaging.xyz` domains and the attacker IP address `167.71.211.113` at the firewall and DNS resolver levels.

**Structural Engineering**
* Configure email security gateways to quarantine or strip `.lnk`, `.iso`, and other potentially dangerous executable formats from inbound attachments, including those nested within encrypted archives.
* Implement advanced DNS filtering and SIEM detection logic to monitor anomalies in DNS requests. Alert on unusually long subdomains (e.g., exceeding 50 characters) or a high volume of unique A-record queries to a single root domain, which strongly indicate DNS tunneling.
* Enable PowerShell Constrained Language Mode via AppLocker/WDAC and centrally collect Script Block Logging (Event ID 4104) to ensure high-fidelity telemetry is available for behavioral detections.
