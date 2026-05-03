---
title: Enes Arda Baydaş
---

<h1 align="center">Enes Arda Baydaş</h1>
<h3 align="center">SOC Analyst Candidate | Building Detection & DFIR Labs</h3>

<p align="center">
Istanbul, Türkiye | Available for Tier 1 SOC Analyst Internship
</p>

<div style="text-align: center; display: flex; justify-content: center; gap: 10px;">
  <a href="https://linkedin.com/in/enesardabaydas">
    <img src="https://img.shields.io/badge/LinkedIn-%230077B5?style=for-the-badge&logo=linkedin&logoColor=white" 
         alt="LinkedIn" 
         style="height: 28px !important; width: auto !important; max-width: none !important;" />
  </a>
  <a href="mailto:enesardabaydas@gmail.com">
    <img src="https://img.shields.io/badge/Gmail-%23D14836?style=for-the-badge&logo=gmail&logoColor=white" 
         alt="Email" 
         style="height: 28px !important; width: auto !important; max-width: none !important;" />
  </a>
</div>

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

## Featured Engineering Projects

* **[Sentinel-Native AI-Augmented Triage Agent](Sentinel%20Native%20Autonomous%20Triage%20Agent.md)**
    * ***Architecture***: Engineered a **bidirectional SOAR-lite pipeline** utilizing **LangGraph StateGraph** with **conditional routing** to dynamically orchestrate a $0-cost triage workflow via **Azure REST APIs** and **Managed Identities** (zero-secret architecture).
    * ***Asynchronous Orchestration***: Leverages `asyncio` and `aiohttp` to bypass synchronous API bottlenecks, executing **concurrent CTI enrichment** (VirusTotal/AbuseIPDB) and parallel incident polling with rate-limit semaphores.
    * ***Deterministic Reliability & Adaptive Learning***: Mitigates LLM unreliability by enforcing **strict Pydantic schemas** and integrating **RAG-based correction loops**, ensuring continuously improving query generation, token-efficient processing, and 100% valid state transitions.
    * ***Resilience & Active Containment***: Combined **Optimistic Concurrency Control (ETags)** for race-condition prevention with **active containment execution** and a **Human-in-the-Loop (HITL)** gate, enabling rapid, high-fidelity threat isolation and robust incident closure.


* **[Autonomous Tier 1 Phishing Triage Pipeline](Autonomous%20Tier%201%20Phishing%20Triage%20Pipeline.md)**
    * ***Architecture**:* Engineered a **two-process SOC automation system** using a LangGraph ReAct AI agent and a FastMCP tool server.
    * ***Capabilities**:* Automates email ingestion, extracts IOCs via Regex, queries **live threat intelligence** (VirusTotal API), and routes verdicts to a SIEM.
    * ***SIEM Integration**:* Configured **Splunk Enterprise** for continuous JSON log ingestion, building a real-time **"Single Pane of Glass"** dashboard for threat distribution and analyst queues.
    * ***Constraints Overcome**:* Managed API rate limits via **asynchronous batch processing loops** and engineered custom JSON log formatters to ensure SIEM compatibility.

## Lab Exercises & Security Write-ups

<!-- PORTFOLIO:START -->

* **[Malware-Analysis](./Malware-Analysis/)**
  * *Static & Dynamic triage of obfuscated payloads (e.g., Cryptbot, Loaders). IOC extraction and MITRE ATT&CK mapping.*
  * [Agent Tesla VBA Dropper](Agent%20Tesla%20VBA%20Dropper.md)
  * [WannaCry Memory Forensics Analysis](WannaCry%20Memory%20Forensics%20Analysis.md)

* **[Network-Forensics](./Network-Forensics/)**
  * *PCAP analysis, C2 traffic identification, and protocol abuse detection.*
  * [ARP Spoofing Competing MITM Analysis](ARP%20Spoofing%20Competing%20MITM%20Analysis.md)
  * [CobaltStrike and IcedID Infection](CobaltStrike%20and%20IcedID%20Infection.md)
  * [PCAP Analysis of SSL Stripping&Credential Theft](SSL%20Stripping%20Analysis.md)
  * [Triage of Local DNS Spoofing Activity](Local%20DNS%20Spoofing%20Activity%20Analysis.md)

* **[SIEM-Hunting](./SIEM-Hunting/)**
  * *Splunk/ELK queries, Sigma rules, and brute-force detection.*
  * [AI As C2 Theoretical Analysis](AI%20as%20C2%20Theoretical_Analysis.md)
  * [BITSAdmin LOLBin C2 Traffic in Kibana](BITSAdmin%20LOLBin%20C2%20Traffic%20in%20Kibana.md)
  * [LOLBin C2 Beaconing Via BITS Jobs](LOLBin%20C2%20Beaconing%20via%20BITS%20Jobs.md)

* **[Incident-Response](./Incident-Response/)**
  * *Forensic timeline reconstruction, live triage, and containment playbooks for active breaches.*
  * [Boogeyman1 Phishing DNS Exfiltration](Boogeyman1%20Phishing%20DNS%20Exfiltration.md)
  * [Boogeyman2 Macro to C2 Memory Analysis](Boogeyman2%20Macro%20to%20C2%20Memory%20Analysis.md)
  * [Tempest IR Follina Killchain](Tempest%20IR%20Follina%20Killchain.md)

* **[Detection-Engineering](./Detection-Engineering/)**
  * *Custom YARA/Snort signatures, proactive alert creation, and false-positive tuning against adversary tradecraft.*
  * [Atomic Red Team Emulation Sysmon Detection](Atomic%20Red%20Team%20Emulation.md)

<!-- PORTFOLIO:END -->
