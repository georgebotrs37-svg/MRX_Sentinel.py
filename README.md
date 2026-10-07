
# MR.X Sentinel

**MR.X Sentinel** is a lightweight Python-based SOC detection and triage platform designed to analyze security logs, detect suspicious activity, extract Indicators of Compromise (IOCs), map detections to MITRE ATT&CK, and generate investigation reports.

The project is built as a practical Blue Team / SOC Analyst lab for learning detection engineering, log analysis, incident triage, and security automation.

---

## Features

### Log Analysis

MR.X Sentinel analyzes security log files and detects suspicious activity such as:

* Failed authentication attempts
* Brute Force activity
* Suspicious PowerShell execution
* Account creation
* Scheduled Task persistence
* Suspicious command-line activity

Example detection:

```text
[HIGH] Suspicious PowerShell
Line    : 6
Evidence: EventID=4688 Process=powershell.exe CommandLine=powershell.exe -enc SQBFAFgA
MITRE   : T1059.001 (PowerShell)
```

---

## IOC Analyzer

The IOC Analyzer extracts security indicators from logs and analyst-provided text.

Supported IOC types:

* IPv4 addresses
* Domains
* URLs
* Email addresses
* MD5 hashes
* SHA1 hashes
* SHA256 hashes

Example:

```text
192.168.1.50
8.8.8.8
malicious-example.com
http://malicious-example.com/test
admin@example.com
d41d8cd98f00b204e9800998ecf8427e
```

IP addresses are also classified as:

```text
PRIVATE
PUBLIC
LOOPBACK
LINK-LOCAL
RESERVED
INVALID
```

---

## MITRE ATT&CK Mapping

Detected behaviors are automatically mapped to relevant MITRE ATT&CK techniques.

| Detection             | MITRE ATT&CK |
| --------------------- | ------------ |
| Suspicious PowerShell | T1059.001    |
| Brute Force           | T1110        |
| Account Creation      | T1136.001    |
| Scheduled Task        | T1053.005    |
| Ingress Tool Transfer | T1105        |
| Account Manipulation  | T1098        |

This allows analysts to understand detected activity from an adversary-behavior perspective.

---

## Alert Severity

MR.X Sentinel categorizes alerts according to severity:

```text
[HIGH]
[MEDIUM]
[LOW]
```

Each alert contains:

* Detection rule
* Severity
* Evidence
* Source
* Log line
* MITRE ATT&CK mapping

Example:

```text
[HIGH] Possible Brute Force

Evidence:
5 failed authentication events from 8.8.8.8

MITRE:
T1110 - Brute Force
```

---

## SQLite SOC Database

MR.X Sentinel stores alerts and incidents in a local SQLite database.

Database:

```text
data/mrx_soc.db
```

The database contains:

### Alerts

```text
id
created_at
severity
rule
evidence
source
```

### Incidents

```text
id
created_at
title
severity
source
ioc
mitre
status
notes
```

This provides persistent storage for SOC investigations.

---

## JSON Reports

After analyzing a log file, MR.X Sentinel can export a JSON investigation report.

Example:

```text
data/reports/mrx_report_YYYYMMDD_HHMMSS.json
```

The report can be used for:

* Incident documentation
* SOC investigation
* Detection testing
* Threat-hunting exercises
* Portfolio demonstrations
* Further automation

---

## SOC Dashboard

The built-in dashboard provides an overview of stored alerts and incidents.

Example menu:

```text
[1] SOC Dashboard
[2] Log Analyzer
[3] IOC Analyzer
[4] MITRE ATT&CK
[5] Create Incident
[6] Network Information
[7] System Information
[8] Recent Incidents
[9] About
[0] Exit
```

---

## Architecture

```text
                    +----------------+
                    |   Log Sources  |
                    +-------+--------+
                            |
                            v
                  +-------------------+
                  | MR.X Log Analyzer |
                  +---------+---------+
                            |
             +--------------+--------------+
             |              |              |
             v              v              v
       Detection       IOC Analysis    MITRE Mapping
          Rules             |              |
             |              |              |
             +--------------+--------------+
                            |
                            v
                    +---------------+
                    | Alert Engine  |
                    +-------+-------+
                            |
                  +---------+---------+
                  |                   |
                  v                   v
            SQLite Database       JSON Report
                  |
                  v
             SOC Dashboard
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/georgebotrs37-svg/MRX-Sentinel.git
cd MRX-Sentinel
```

Make sure Python 3.10+ is installed:

```bash
python --version
```

No external Python packages are required for the core version.

---

## Running MR.X Sentinel

Start the interactive interface:

```bash
python MRX_Sentinel.py
```

You should see:

```text
========================================
          MR.X SENTINEL
      SOC Detection Platform
========================================

[1] SOC Dashboard
[2] Log Analyzer
[3] IOC Analyzer
[4] MITRE ATT&CK
[5] Create Incident
[6] Network Information
[7] System Information
[8] Recent Incidents
[9] About
[0] Exit
```

---

## Log Analysis Example

Select:

```text
MR.X >>> 2
```

Then provide the log file:

```text
Log file path: data\test_logs\sample.log
```

MR.X analyzes the file and generates detections.

Example output:

```text
[ ALERTS ]

01. [HIGH] Suspicious PowerShell
    MITRE: T1059.001 (PowerShell)

02. [MEDIUM] Possible Account Creation
    MITRE: T1136.001 (Create Account: Local Account)

03. [HIGH] Possible Scheduled Task Persistence
    MITRE: T1053.005 (Scheduled Task)

04. [HIGH] Possible Brute Force
    MITRE: T1110 (Brute Force)
```

---

## Test Log

A simple test log can contain events such as:

```text
EventID=4625 AccountName=admin SourceIP=8.8.8.8 Status=Failed
EventID=4625 AccountName=admin SourceIP=8.8.8.8 Status=Failed
EventID=4625 AccountName=admin SourceIP=8.8.8.8 Status=Failed
EventID=4625 AccountName=admin SourceIP=8.8.8.8 Status=Failed
EventID=4625 AccountName=admin SourceIP=8.8.8.8 Status=Failed

EventID=4688 Process=powershell.exe CommandLine=powershell.exe -enc SQBFAFgA

EventID=4720 AccountName=backdoor UserCreated=true

EventID=4698 TaskName=WindowsUpdateUpdater ScheduledTask=true
```

The expected detections include:

```text
Brute Force
Suspicious PowerShell
Account Creation
Scheduled Task Persistence
```

---

## Project Structure

```text
MRX-Sentinel/
│
├── MRX_Sentinel.py
│
├── data/
│   ├── mrx_soc.db
│   │
│   ├── test_logs/
│   │   └── sample.log
│   │
│   └── reports/
│       └── mrx_report_*.json
│
└── README.md
```

---

## Detection Workflow

The project follows a simplified SOC workflow:

```text
1. Collect
      ↓
2. Parse
      ↓
3. Detect
      ↓
4. Extract IOCs
      ↓
5. Map to MITRE ATT&CK
      ↓
6. Assign Severity
      ↓
7. Store Alert
      ↓
8. Create Incident
      ↓
9. Export Report
```

---

## Blue Team Use Cases

MR.X Sentinel can be used to practice:

* SOC Alert Triage
* Log Analysis
* Detection Engineering
* IOC Extraction
* MITRE ATT&CK Mapping
* Brute Force Detection
* PowerShell Detection
* Windows Event Analysis
* Incident Documentation
* Security Automation
* Threat Hunting fundamentals

---

## Roadmap

Future improvements planned for MR.X Sentinel:

* [ ] Improved IOC validation
* [ ] False-positive reduction
* [ ] Risk scoring engine
* [ ] Detection timeline
* [ ] More Windows Event IDs
* [ ] Sysmon support
* [ ] Sigma rule support
* [ ] YARA integration
* [ ] Threat Intelligence integration
* [ ] AbuseIPDB integration
* [ ] VirusTotal integration
* [ ] Wazuh integration
* [ ] Splunk integration
* [ ] Web-based SOC dashboard
* [ ] Automated incident response
* [ ] Email/Telegram alerting
* [ ] Advanced MITRE ATT&CK coverage

---

## Disclaimer

MR.X Sentinel is intended for:

* Defensive security research
* SOC training
* Blue Team labs
* Authorized security testing
* Detection engineering
* Educational purposes

Only analyze systems and logs that you own or have explicit permission to investigate.

---

## Author

**George Botrs**

Cybersecurity Professional | SOC Analyst | Full Stack Developer

Project: **MR.X Sentinel**

Brand: **MR.X**

---

## License

This project is intended for educational and defensive cybersecurity purposes.

Use responsibly.
