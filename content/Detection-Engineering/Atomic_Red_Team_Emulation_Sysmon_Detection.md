### Detection Engineering: Validating Telemetry and Telemetry Gaps via Threat Emulation

**Date:** 2026-04-22  

**Author:** Enes Arda Baydaş  

**Environment:** TryHackMe (Atomic Bird Goes Purple)  

**Framework:** Atomic Red Team

**MITRE ATT&CK:** T1082, T1056.002, T1091, T1552.001, T1543.003, T1491

---

### Summary
This engagement utilized the Atomic Red Team framework to simulate advanced persistent threat (APT) behaviors, specifically targeting execution, discovery, and persistence mechanisms. The primary objective was not to block the attack, but to validate the telemetry pipelines (Aurora EDR, Sysmon) and engineer behavioral detection logic that remains resilient against adversary tooling variations.

---

```mermaid
graph LR
    A[Atomic Red Team Emulation] --> B(T1082 / T1056 Discovery & Prompt)
    A --> C(T1091 File Manipulation)
    A --> D(T1543.003 Service Persistence)
    A --> E(T1491 File Defacement)
    B --> F[Sysmon & Windows Event Logs]
    C --> F
    D --> F
    E --> F
    F --> G[Detection Rule Engineering]
````

## Emulation & Detection Engineering

Instead of relying on fragile, static indicators (e.g., specific file hashes or predefined service names), the resulting detection logic focuses on immutable adversary behaviors at the choke points of their attack lifecycle.

### 1. Persistence: Anomalous Service Creation via Registry (T1543.003)
**Hypothesis**: Adversaries must create or modify services to maintain persistence. Rather than using standard Windows APIs (sc.exe), they may directly manipulate the registry to evade basic monitoring.

**Telemetry Source**: Sysmon Event ID 13 (Registry Value Set)

**Behavioral Chokepoint**: Legitimate service modifications are typically handled by services.exe, msiexec.exe, or approved configuration management agents. Modifications originating from script interpreters (PowerShell.exe, cmd.exe) or unapproved binaries are highly anomalous.

<img width="1559" height="726" alt="Pasted image 20260415133058" src="https://github.com/user-attachments/assets/30ca61fa-56eb-41fe-9d6f-833227de2442" />

**Example Detection Logic (Splunk SPL):**

```Splunk SPL
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 
TargetObject="*\\System\\CurrentControlSet\\Services\\*\\Start" 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, Image, TargetObject, Details 
| search NOT (Image IN ("*\\Windows\\System32\\services.exe", "*\\Windows\\System32\\msiexec.exe", "*\\Program Files\\*\\Update.exe"))
| convert ctime(firstTime) ctime(lastTime)
```
Tuning Note: The NOT statement establishes the baseline. In a production environment, this must be expanded to include SCCM, Intune, or other enterprise management tools.

### 2. Impact: High-Velocity File Modification / Defacement (T1491)
**Hypothesis**: Ransomware or data destruction operations require rapid modification of files across the file system. Detection must focus on the velocity of file writes/renames by a single process.

**Telemetry Source**: Sysmon Event ID 11 (File Create) or Windows Security Event ID 4663 (File System Auditing)

**Behavioral Chokepoint**: A single, non-backup process rapidly generating file creation or modification events across user directories.

**Example Detection Logic (Splunk SPL):**

```Splunk SPL
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
TargetFilename="*\\Users\\*"
| bin _time span=1m
| stats dc(TargetFilename) as modified_files_count values(TargetFilename) as files by _time, Computer, Image
| where modified_files_count > 50
| search NOT (Image IN ("*\\Windows\\System32\\wbem\\WmiPrvSE.exe", "*\\Program Files\\BackupTool\\backup.exe"))
```
Tuning Note: The threshold of > 50 per minute per process is a starting hypothesis. This must be tuned against a 30-day historical baseline to identify legitimate high-volume processes (e.g., developers compiling code, users extracting large zip files) and add them to the exclusion list.

### 3. Credential Access: Simulated Authentication Prompts (T1056.002)
**Hypothesis**: Attackers use spoofed GUI prompts to harvest credentials.

**Telemetry Gap Identified**: While the emulation successfully launched a spoofed "SESSION EXPIRED" prompt, relying solely on process creation logs (Event ID 1) for the specific PowerShell payload is brittle.

**Remediation Recommendation**: Implement UI/Window title monitoring within the EDR if supported, or engineer rules looking for PowerShell/Command Prompt executions containing parameters related to drawing forms (e.g., System.Windows.Forms).

<img width="1827" height="906" alt="Pasted image 20260409165231" src="https://github.com/user-attachments/assets/8332c8b5-31cd-45cf-88d6-acdb37d13c90" />
