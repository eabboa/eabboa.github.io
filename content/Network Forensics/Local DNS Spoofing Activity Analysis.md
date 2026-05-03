# Network Forensics: Triage of Local DNS Spoofing Activity

**Date:** 2026-03-04

**Author:** Enes Arda Baydaş

**Category:** Network Forensics

**Platform:** THM / Adversary-in-the-Middle Detection

````mermaid
flowchart LR

classDef input fill:#4A90D9,color:#fff

classDef process fill:#6B7280,color:#fff

classDef decision fill:#F59E0B,color:#fff

classDef output fill:#10B981,color:#fff

subgraph Triage

I1([Detect Anomalous DNS])

P1[Filter DNS Responses]

P2[Identify Rogue IP]

end

subgraph Analysis

D1{Is Spoofing Confirmed}

P3[Analyze Other Causes]

end

subgraph Remediation

O1[[Isolate Attacker Host]]

O2[[Flush Victim Caches]]

O3[[Apply Network Hardening]]

end

I1 --> P1

P1 --> P2

P2 --> D1

D1 -->|Yes| O1

D1 -->|No| P3

O1 --> O2

O2 --> O3

class I1 input

class P1,P2,P3 process

class D1 decision

class O1,O2,O3 output
````

### 1. Executive Brief

**Scenario:** A network packet capture (PCAP) analysis investigated anomalous DNS resolution targeting the internal corporate login portal (`corp-login.acme-corp.local`).

**Goal:** Isolate anomalous DNS traffic, identify the rogue responding source, and confirm active Adversary-in-the-Middle (AitM) execution.

**Business Impact:** DNS spoofing enables silent redirection to fraudulent infrastructure for credential harvesting. Unmitigated, this results in unauthorized network access and compromise of corporate accounts.

### 2. The Investigation

**Trigger:** Unsolicited DNS responses and multiple responses for a single query ID originating from an unauthorized internal source IP.

**Analysis:** MITRE ATT&CK T1557 (Adversary-in-the-Middle) / T1557.001 (ARP/DNS Poisoning)

Initial triage isolated DNS response packets to identify unauthorized resolvers using the Wireshark filter `dns.flags.response==1`.

<img width="1920" height="1200" alt="Pasted image 20260220133404" src="https://github.com/user-attachments/assets/4a8d5fa4-a3a3-4414-9517-943d80e950e6" />


**Observation:** An unauthorized internal IP address generated DNS replies for the corporate login portal.

**Inference:** A rogue host is attempting to poison local DNS caches.

Scope was narrowed to the targeted domain: `dns && dns.qry.name == "corp-login.acme-corp.local"`.

<img width="1920" height="1200" alt="Pasted image 20260220133603" src="https://github.com/user-attachments/assets/be55e8bd-374e-400e-b570-c993988d70d0" />


**Observation:** Victim host (`192.168.10.10`) generated legitimate DNS requests for the internal login portal. The rogue response successfully matched the victim's DNS Transaction ID (`dns.id`), a strict prerequisite for successful cache poisoning.

**Inference:** The attacker is actively monitoring local traffic to inject malicious responses matching the victim's request parameters.

Legitimate responses from the authorized internal domain controller/DNS server (`192.168.10.2`) were filtered out: `dns.flags.response == 1 && ip.src != 192.168.10.2 && dns.qry.name == "corp-login.acme-corp.local"`. Layer 2 analysis was conducted alongside this to verify routing manipulation.

<img width="1920" height="1200" alt="Pasted image 20260220133734" src="https://github.com/user-attachments/assets/567ba226-3f51-478e-8d62-8200dfde2826" />

**Observation:** Host `192.168.10.55` masqueraded as the legitimate DNS server. Layer 2 analysis confirmed this was preceded by gratuitous ARP broadcasts from the attacker's MAC address, establishing the network intercept.

**Inference:** DNS spoofing and ARP poisoning are confirmed. The rogue device (`192.168.10.55`) is intercepting victim traffic to execute a redirection attack.

### 3. Findings & Artifacts (IOCs)

|**Artifact Type**|**Value**|**Context**|
|---|---|---|
|**Malicious IP**|`192.168.10.55`|Rogue DNS responder (Attacker)|
|**Targeted Domain**|`corp-login.acme-corp.local`|Intended spoofing target|
|**Victim IP**|`192.168.10.10`|Host receiving poisoned DNS records|
|**Spoofed Service**|`192.168.10.2`|Authorized internal DNS server impersonated|

### 4. Remediation & Hardening

**Immediate Containment:**

- Isolate host `192.168.10.55` from the network to halt the AitM attack.
    
- Execute `ipconfig /flushdns` and `arp -d *` on the victim machine (`192.168.10.10`) to clear poisoned caches.
    
- Force a password reset for the user associated with the victim machine.
    

**Strategic Hardening:**

- Enforce HTTPS and HTTP Strict Transport Security (HSTS) on the `corp-login` portal to neutralize credential harvesting via downgrade or redirection attacks, rendering DNS spoofing ineffective against the application.
    
- Implement Dynamic ARP Inspection (DAI) and DHCP Snooping on network switches to prevent Layer 2 manipulation.
    
- Configure SIEM alerts for short DNS Time-To-Live (TTL) values, duplicate DNS responses to a single query ID, and unauthorized internal hosts responding on port 53.
    
- If external infrastructure was involved in the redirect payload, document and share indicators with USOM for national threat intelligence tracking.
