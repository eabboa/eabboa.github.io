---
title: Enes Arda Baydaş
---
Istanbul, Türkiye

## What I Build
I take manual SOC workflows apart and rebuild them as asynchronous, AI-augmented
pipelines — systems that do the collection and enrichment an analyst would
otherwise do by hand, and hand back a verdict.

*Second-year MIS student at Marmara University.*

## Proof of Work

### ⚙️ Engineering & Automation
* **[Sentinel-Native AI-Augmented Triage Agent](Sentinel%20Native%20AI-Augmented%20Triage%20Agent.md):**
  A triage workflow on LangGraph and the Azure REST APIs, running with no stored
  credentials and no infrastructure cost. Replaced blocking API calls with
  `asyncio`, so CTI enrichment and incident polling run concurrently.
* **[Autonomous Tier 1 Phishing Triage Pipeline](Autonomous%20Tier%201%20Phishing%20Triage%20Pipeline.md):**
  A two-process SOC automation system pairing a LangGraph ReAct agent with a
  FastMCP tool server. Handles email ingestion and live threat intelligence
  lookups, then routes verdicts into Splunk.

### 🔬 Lab Research & Write-ups
* **[Malware Analysis](Malware-Analysis):** Static and dynamic triage of
  obfuscated payloads (Cryptbot, loaders). Memory forensics on WannaCry and
  Agent Tesla VBA droppers.
* **[Network Forensics](Network-Forensics):** PCAP analysis of C2 traffic,
  ARP and DNS spoofing, Cobalt Strike and IcedID infections.
* **[Detection Engineering](Detection-Engineering) & [SIEM Hunting](SIEM-Hunting):**
  Splunk and ELK hunting, custom YARA and Snort signatures, Atomic Red Team
  emulation against Sysmon.
* **[Incident Response](Incident-Response):** Playbook containment and forensic
  timeline reconstruction on live breach scenarios (Boogeyman, Follina).

## Certifications
* **Microsoft SC-200** — Security Operations Analyst
* **[CompTIA Security+](https://www.credly.com/badges/81193545-fc7d-464f-98f3-d27dd681e688/linked_in_profile)** (810/900)
* Ongoing practice: CyberDefenders, custom home labs

## Technical Arsenal
* **Frameworks:** MITRE ATT&CK®, MITRE D3FEND™, Unified Kill Chain
* **Cloud & Automation:** Azure, Entra ID, LangGraph
* **SIEM / EDR:** Microsoft Sentinel, Splunk (SPL), Elastic (ELK), Sysmon
* **Network Analysis:** Wireshark, Snort, Zeek, Brim