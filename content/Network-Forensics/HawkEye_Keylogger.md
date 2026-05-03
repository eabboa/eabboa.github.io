# Network Forensics Analysis: HawkEye Keylogger Reborn v9

**Date:** May 3, 2026

**Author:** Enes Arda Baydaş

**Environment:** Network PCAP (CyberDefenders HawkEye)

**Domain:** Network Forensics

**MITRE ATT&CK Matrix:**

- **Initial Access:** T1566 (Phishing)
    
- **Credential Access:** T1056.001 (Keylogging), T1552.001 (Credentials In Files)
    
- **Command and Control:** T1071.003 (Application Layer Protocol: Mail Protocols)
    
- **Exfiltration:** T1048.003 (Exfiltration Over Alternative Protocol: Unencrypted/Obfuscated), T1029 (Scheduled Transfer)

## Executive Summary

Network forensic analysis of the `BEIJING-5CD1-PC` host revealed an active infection by the **HawkEye Keylogger Reborn v9** malware variant. The payload, identified as `tkraw_Protected99.exe`, systematically harvested local system credentials, browser-stored passwords, and keystrokes. The adversary established an automated exfiltration pipeline, transmitting base64-encoded credential dumps via authenticated SMTP to an external mail server (`sales[.]del@macwinlogistics[.]in`) on a rigid 10-minute interval. Critical financial (Bank of America) and communication (AOL, Outlook) credentials were compromised.

## Indicators of Compromise (IoCs)

| **Type**       | **Indicator**                      | **Context**                      |
| -------------- | ---------------------------------- | -------------------------------- |
| **IPv4**       | `217[.]182[.]138[.]150`            | Delivery Domain Hosting (France) |
| **Domain**     | `proforma-invoices[.]com`          | Payload Delivery Server          |
| **Hash (MD5)** | `71826BA081E303866CE2A2534491A2F7` | `tkraw_Protected99.exe`          |
| **Email**      | `sales[.]del@macwinlogistics[.]in` | Exfiltration Destination         |
| **Keyword**    | `HawkEye Keylogger Reborn v9`      | Base64 Encoded SMTP Subject      |

## Execution Flow & Network Impact

``````mermaid
graph TD
    A[Victim: BEIJING-5CD1-PC] -->|HTTP GET| B[proforma-invoices.com]
    B -->|tkraw_Protected99.exe| C[Local Host Execution]
    C -->|T1552: Credential Access| D[Extracts AOL, BOA, & Outlook Data]
    D -->|Base64 Encoding| E[Staged Data for Exfiltration]
    E -->|SMTP Auth: Sales@23| F[Target: sales..del@macwinlogistics..in]
    F -->|T1029: Scheduled Transfer| G[Repeats Every 10 Minutes]
    
    style A fill:#f9f,stroke:#333,stroke-width:2px
    style B fill:#ffb3ba,stroke:#333,stroke-width:2px
    style F fill:#ffb3ba,stroke:#333,stroke-width:2px
``````
### 1. Payload Delivery

The host initiated an outbound connection to a France-hosted LiteSpeed web server (`proforma-invoices[.]com` / `217[.]182[.]138[.]150`). The victim downloaded the malicious executable, bypassing network edge defenses.

- **File Name:** `tkraw_Protected99.exe`
    
- **MD5 Hash:** `71826BA081E303866CE2A2534491A2F7`

### 2. Credential Access & Staging

Post-execution, the malware targeted local credential stores and applications. Packet stream analysis of the unencrypted SMTP traffic revealed the exact contents of the staged data prior to exfiltration.

HawkEye successfully extracted credentials from:

- **Google Chrome:** Bank of America (`roman[.]mcguire` / `P@ssword$`)
    
- **Internet Explorer (7.0/9.0):** AOL (`roman.mcguire914@aol[.]com` / `P@ssword$`)
    
- **MS Outlook (2002-2010):** POP3/SMTP configurations (`roman[.]mcguire@pizzajukebox[.]com`)

### 3. Exfiltration Protocol (SMTP)

The adversary utilized a compromised or actor-controlled US-based Exim 4.91 mail server (`p3plcpnl0413[.]prod[.]phx3[.]secureserver[.]net`) to exfiltrate the staged data.

<img width="1920" height="1200" alt="Pasted image 20260503092509" src="https://github.com/user-attachments/assets/b54e83ab-be12-4e06-8287-3817dca0ae23" />

- **Exfiltration Target:** `sales[.]del@macwinlogistics[.]in`
    
- **Authentication Mechanism:** SMTP AUTH LOGIN
    
- **Compromised SMTP Credentials:** Username: `c2FsZXMuZGVsQG1hY3dpbmxvZ2lzdGljcy5pbg==` (sales[.]del@macwinlogistics[.]in) | Password: `U2FsZXNAMjM=` (Sales@23)
    
- **Data Encoding:** The email subject and body were base64 encoded. Decoding the subject line revealed the exact malware signature: `HawkEye Keylogger Reborn v9 Passwords Logs roman[.]mcguire BEIJING-5CD1-PC 173[.]66[.]146[.]112`.

<img width="1919" height="842" alt="Pasted image 20260503093014" src="https://github.com/user-attachments/assets/714be270-7399-4952-8cb1-164dceb18bf7" />

The network traffic analysis explicitly confirms a scheduled transfer (T1029), with the compromised system consistently beaconing out the stolen logs every 10 minutes.

## Unresolved Gaps & Forensic Limitations

- **Initial Delivery Vector Missing:** The provided PCAP captures the HTTP download of the payload but does not contain the preceding email traffic or IM chat logs that delivered the initial `proforma-invoices[.]com` link to the user.
    
- **Host-Based Artifacts Unknown:** Because analysis was strictly limited to network captures, the exact persistence mechanisms (e.g., Run keys, Scheduled Tasks) established by `tkraw_Protected99.exe` on the local Windows NT 6.1 host cannot be verified.