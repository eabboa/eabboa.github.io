---
title: Enes Arda Baydaş
---

<h1 align="center">Enes Arda Baydaş</h1>
<h3 align="center">SOC Analyst Candidate | Building Detection & DFIR Labs</h3>

<p align="center">
Istanbul, Türkiye | Available for Tier 1 SOC Analyst Internship
</p>

<p align="center">
  <a href="https://linkedin.com/in/enesardabaydas"><img src="https://img.shields.io/badge/LinkedIn-blue?style=for-the-badge&logo=linkedin" height="30"/></a>
  <a href="mailto:enesardabaydas@gmail.com"><img src="https://img.shields.io/badge/Gmail-D14836?style=for-the-badge&logo=gmail&logoColor=white" height="30" /></a>
</p>
## About Me
SOC Analyst candidate building **proactive threat detection** and malware triage pipelines. Specialized in **custom lab environments** and **automation**. Currently a First-year Management Information Systems student at Marmara University.

##  Certifications & Continuous Learning

[CompTIA Security+](https://www.credly.com/badges/81193545-fc7d-464f-98f3-d27dd681e688/linked_in_profile)

[TryHackMe SOC Level 1](https://tryhackme-certificates.s3-eu-west-1.amazonaws.com/THM-DHTCNMB2AY.pdf)

## Technical Arsenal
| Category | Tools & Frameworks |
| :--- | :--- |
| **Security Frameworks** | MITRE ATT&CK®, MITRE D3FEND™, Cyber Kill Chain, Unified Kill Chain |
| **Cloud Security & Automation** | Microsoft Azure, Microsoft Entra ID, LangGraph |
| **Network Traffic Analysis** | Wireshark, Snort, NetworkMiner, Zeek, Brim |
| **SIEM & Log Management** | Microsoft Sentinel (KQL), Splunk (SPL), Elastic (ELK) |
| **Endpoint Monitoring** |	Windows Event Logs & Sysmon |
---

### Featured Engineering Projects

* **[Sentinel-Native AI-Augmented Triage Agent](https://github.com/eabboa/eabboa/blob/main/Home-Labs/Sentinel_Native_AI_Augmented_Triage_Agent.md)**
    * ***Architecture***: Engineered a **bidirectional SOAR-lite pipeline** utilizing **LangGraph StateGraph** with **conditional routing** to dynamically orchestrate a $0-cost triage workflow via **Azure REST APIs** and **Managed Identities** (zero-secret architecture).
    * ***Asynchronous Orchestration***: Leverages `asyncio` and `aiohttp` to bypass synchronous API bottlenecks, executing **concurrent CTI enrichment** (VirusTotal/AbuseIPDB) and parallel incident polling with rate-limit semaphores.
    * ***Deterministic Reliability & Adaptive Learning***: Mitigates LLM unreliability by enforcing **strict Pydantic schemas** and integrating **RAG-based correction loops**, ensuring continuously improving query generation, token-efficient processing, and 100% valid state transitions.
    * ***Resilience & Active Containment***: Combined **Optimistic Concurrency Control (ETags)** for race-condition prevention with **active containment execution** and a **Human-in-the-Loop (HITL)** gate, enabling rapid, high-fidelity threat isolation and robust incident closure.


* **[Autonomous Tier 1 Phishing Triage Pipeline](https://github.com/eabboa/eabboa/blob/main/Home-Labs/Autonomous_Tier_1_Phishing_Triage_Pipeline.md)**
    * ***Architecture**:* Engineered a **two-process SOC automation system** using a LangGraph ReAct AI agent and a FastMCP tool server.
    * ***Capabilities**:* Automates email ingestion, extracts IOCs via Regex, queries **live threat intelligence** (VirusTotal API), and routes verdicts to a SIEM.
    * ***SIEM Integration**:* Configured **Splunk Enterprise** for continuous JSON log ingestion, building a real-time **"Single Pane of Glass"** dashboard for threat distribution and analyst queues.
    * ***Constraints Overcome**:* Managed API rate limits via **asynchronous batch processing loops** and engineered custom JSON log formatters to ensure SIEM compatibility.

## Lab Exercises & Security Write-ups

<!-- PORTFOLIO:START -->

* **[Malware-Analysis](./Malware-Analysis/)**
  * *Static & Dynamic triage of obfuscated payloads (e.g., Cryptbot, Loaders). IOC extraction and MITRE ATT&CK mapping.*
  * [Agent Tesla VBA Dropper](./Malware-Analysis/Agent_Tesla_VBA_Dropper.md)
  * [WannaCry Memory Forensics Analysis](./Malware-Analysis/WannaCry_Memory_Forensics_Analysis.md)

* **[Network-Forensics](./Network-Forensics/)**
  * *PCAP analysis, C2 traffic identification, and protocol abuse detection.*
  * [ARP Spoofing Competing MITM Analysis](./Network-Forensics/ARP_Spoofing_Competing_MITM_Analysis.md)
  * [CobaltStrike and IcedID Infection](./Network-Forensics/CobaltStrike-and-IcedID-Infection.md)
  * [PCAP Analysis of SSL Stripping&Credential Theft](./Network-Forensics/PCAP_Analysis_of_SSL_Stripping&Credential_Theft.md)
  * [Triage of Local DNS Spoofing Activity](./Network-Forensics/Triage_of_Local_DNS_Spoofing_Activity.md)

* **[SIEM-Hunting](./SIEM-Hunting/)**
  * *Splunk/ELK queries, Sigma rules, and brute-force detection.*
  * [AI As C2 Theoretical Analysis](./SIEM-Hunting/AI_as_C2_Theoretical_Analysis.md)
  * [BITSAdmin LOLBin C2 Kibana](./SIEM-Hunting/BITSAdmin_LOLBin_C2_Kibana.md)
  * [LOLBin C2 Beaconing Via BITS Jobs](./SIEM-Hunting/LOLBin_C2_Beaconing_via_BITS_Jobs.md)

* **[Incident-Response](./Incident-Response/)**
  * *Forensic timeline reconstruction, live triage, and containment playbooks for active breaches.*
  * [Boogeyman1 Phishing DNS Exfiltration](./Incident-Response/Boogeyman1_Phishing_DNS_Exfiltration.md)
  * [Boogeyman2 Macro to C2 Memory Analysis](./Incident-Response/Boogeyman2_Macro_to_C2_Memory_Analysis.md)
  * [Tempest IR Follina Killchain](./Incident-Response/Tempest_IR_Follina_Killchain.md)

* **[Detection-Engineering](./Detection-Engineering/)**
  * *Custom YARA/Snort signatures, proactive alert creation, and false-positive tuning against adversary tradecraft.*
  * [Atomic Red Team Emulation Sysmon Detection](./Detection-Engineering/Atomic_Red_Team_Emulation_Sysmon_Detection.md)

<!-- PORTFOLIO:END -->
