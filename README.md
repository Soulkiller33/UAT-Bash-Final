# UAT-Bash-Final
# ONLY SCAN TARGETS YOU ARE PERMITTED TO SCAN #
# Automated Network Security Scanner

## Overview
A Bash automation script that scans target networks or hosts for open ports, vulnerabilities, and web misconfigurations by combining a custom Python port scanner, advanced Nmap scans, and Nikto assessments.

---

## Features
* **Privilege & Input Validation:** Requires `sudo` and validates command-line target inputs with error handling.
* **Automated Setup:** Installs prerequisites (`nmap`, `python3`, `git`, `nikto`) and clones required repositories automatically.
* **Target Reachability:** Performs ICMP ping checks before scanning with an option to abort or force execution.
* **Reporting:** Generates structured reports with executive summaries, CVE listings, remediation steps, and timestamped archives.

---

## Usage
Run with root privileges and specify a target IP or hostname:

### Default Port Scan (All standard ports)
```bash
sudo ./scanner.sh <target_ip_or_hostname>```
