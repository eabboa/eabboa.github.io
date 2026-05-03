# Network Traffic Analysis: ARP Spoofing and Competing MITM Actors

**Date:** 2026-02-20

**Author:** Enes Arda Baydaş

**Category:** Network Forensics

**Lab Source:** TryHackMe (Room: Man-in-the-Middle Detection)

#### Key Takeaways

- Successfully identified and isolated overlapping Adversary-in-the-Middle (AiTM) attacks within a noisy network capture.
    
- Demonstrated proficiency in filtering and analyzing Layer 2 protocols (ARP) to detect unauthorized network manipulation.
    
- Formulated enterprise-grade remediation strategies, including Dynamic ARP Inspection (DAI), to prevent Layer 2 poisoning

### 1. Simulated Impact

Analysis of the provided network capture (`network_traffic.pcap`) confirmed an active Adversary-in-the-Middle (AiTM) attack targeting the local network gateway (`192.168.10.1`). 

Two distinct rogue devices were observed conducting simultaneous Address Resolution Protocol (ARP) cache poisoning. 

This activity allows the unauthorized interception and potential manipulation of outbound subnet traffic. Immediate isolation of the offending switch ports is required.

### 2. The Investigation

**Trigger:** Identification of a disproportionately high volume of ARP broadcasts within the standard network traffic baseline.

**Analysis:** This activity maps directly to **MITRE ATT&CK T1557.002** (Adversary-in-the-Middle: ARP Cache Poisoning).

The PCAP file was initially filtered using `arp.opcode == 1` to establish a baseline of standard "who-has" requests. Subsequently, the filter was shifted to `arp.opcode == 2` to analyze "is-at" responses. This revealed a significant flood of Gratuitous ARP (GARP) messages, unsolicited replies typically used for hardware changes or failover, but highly suspicious in this volume.

<img width="802" height="155" alt="image" src="https://github.com/user-attachments/assets/77058728-3bc2-427e-ad57-05d9a092331a" />


- **Observation:** A single host associated with MAC address `02:aa:bb:cc:00:01` was aggressively broadcasting itself as the owner of the gateway IP address (`192.168.10.1`). 

- **Inference:** This is a definitive indicator of an active ARP spoofing attempt. The malicious host is attempting to poison the ARP caches of other devices on the subnet, forcing them to route outbound traffic through the attacker's machine rather than the legitimate router.

Further refinement of the display filter (`arp.opcode == 2 && arp.src.proto_ipv4 == 192.168.10.1`) uncovered an escalation in the attack pattern.

<img width="804" height="322" alt="image" src="https://github.com/user-attachments/assets/f08cbeb7-3415-48eb-899d-13c2eeb41254" />


- **Observation:** Two distinct MAC addresses (`02:aa:bb:cc:00:01` and `02:fe:fe:fe:55:55`) were observed continuously transmitting Gratuitous ARP replies, both asserting ownership of the gateway IP (`192.168.10.1`).

- **Inference:** Two separate malicious actors (or misconfigured rogue devices) are simultaneously executing ARP poisoning attacks. They are actively competing for the MITM position on the same network segment, creating a "**tug-of-war**" for routing dominance.

### 3. Findings & Artifacts (IOCs)

|**Indicator Type**|**Value**|**Context**|
|---|---|---|
|**Target Gateway IP**|`192.168.10.1`|Spoofed IP Address|
|**Malicious MAC A**|`02:aa:bb:cc:00:01`|Rogue device asserting gateway ownership|
|**Malicious MAC B**|`02:fe:fe:fe:55:55`|Secondary rogue device asserting gateway ownership|
|**Attack Vector**|GARP Flooding|Abuse of ARP `opcode 2` without preceding `opcode 1`|

### 4. Remediation & Hardening

**Immediate Mitigation:**

1. **Port Isolation:** Administratively disable the physical switch ports terminating the connections for MAC addresses `02:aa:bb:cc:00:01` and `02:fe:fe:fe:55:55`.
    
2. **Cache Clearance:** Execute ARP cache flushes (`arp -d *` or OS equivalent) on all affected subnet endpoints and the local router to force re-resolution of the legitimate gateway MAC.
    

**Long-Term Prevention (Root Cause Fix):**

1. **Dynamic ARP Inspection (DAI):** Implement DAI on all managed switches. This enforces strict IP-to-MAC binding verification by cross-referencing ARP packets against the DHCP snooping binding database, dropping invalid payloads.
    
2. **Port Security:** Enable strict MAC address limiting per switch port to prevent rogue devices from easily connecting and flooding the segment.
