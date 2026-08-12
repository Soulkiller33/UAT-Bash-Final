#!/bin/bash

# ==============================================================================
# Script Name: Automated Network Security Scanner
# Description: Performs target validation, runs a custom Python port scanner,
#              executes an advanced Nmap vulnerability scan, runs Nikto for web 
#              assets, and compiles a comprehensive report.
# ==============================================================================

# Exit immediately if a command exits with a non-zero status
set -e

# --- FUNCTIONS ---

# Function: Display usage and exit
print_usage() {
    echo "[-] Error: Invalid arguments provided." >&2
    echo "Usage: sudo $0 <target_ip_or_hostname> [ports]" >&2
    echo "Example: sudo $0 192.168.1.100 80,443" >&2
    exit 1
}

# Function: Check for root privileges
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "[-] Error: This script must be run with root privileges (sudo)." >&2
        exit 1
    fi
}

# Function: Install prerequisites
install_prerequisites() {
    echo "[*] Updating package lists and installing prerequisites..."
    sudo apt-get update && sudo apt-get install -y nmap python3 git nikto || {
        echo "[-] Error: Failed to install prerequisites." >&2
        exit 1
    }
    echo -e "[+] Prerequisites installed successfully.\n"
}

# Function: Setup workspace directories and clone custom scripts
setup_workspace() {
    if [ -d "Bash_Scanner" ]; then
        cd Bash_Scanner
        echo "[*] Bash_Scanner directory exists. Entering directory."
    else 
        mkdir Bash_Scanner && cd Bash_Scanner
        echo "[+] Bash_Scanner directory created and entered."
    fi

    if [ -d "PythonScriptForBash" ]; then
        cd PythonScriptForBash
        echo "[*] PythonScriptForBash repository already exists. Entering directory."
    else
        git clone https://github.com/Soulkiller33/PythonScriptForBash || {
            echo "[-] Error: Failed to clone PythonScriptForBash repository." >&2
            exit 1
        }
        echo "[+] PythonScriptForBash repository cloned successfully."
        cd PythonScriptForBash
    fi
    echo -e "\n--- Environment setup completed ---\n"
}

# Function: Validate target reachability
validate_target() {
    local target="$1"
    echo "[*] Checking if target $target is online..."
    if ! ping -c 1 -W 2 "$target" &> /dev/null; then
        echo "[-] Warning: Target host $target is unreachable or blocking ICMP ping." >&2
        read -p "[?] Proceed with scan anyway? (y/N): " FORCE_SCAN
        if [[ ! "$FORCE_SCAN" =~ ^[Yy]$ ]]; then
            echo "[-] Aborting scan."
            exit 1
        fi
    else
        echo "[+] Host is online and responding."
    fi
}

# --- MAIN EXECUTION ---

# 1. Enforce root privileges
check_root

# 2. Strict Input Validation: Ensure exactly one target argument is provided
if [ -z "$1" ]; then
    print_usage
fi

TARGET_IP="$1"

# Clean up optional port argument if passed via $2
PORTS_CLEAN=$(echo "$2" | sed 's/-p//g' | tr -d ' ')

NMAP_PORT=""
PYTHON_PORT=""
if [ -n "$PORTS_CLEAN" ]; then
    NMAP_PORT="-p $PORTS_CLEAN"
    PYTHON_PORT="--ports $PORTS_CLEAN"
fi

# 3. Setup Environment & Dependencies
install_prerequisites
setup_workspace

# 4. Validate Target Reachability
validate_target "$TARGET_IP"

# 5. Initialize Raw Scan Log
RAW_LOG="raw_scan.tmp"
echo "==================================================" > "$RAW_LOG"
echo "       AUTOMATED NETWORK SECURITY REPORT          " >> "$RAW_LOG"
echo "==================================================" >> "$RAW_LOG"
echo "Target IP/Host : $TARGET_IP" >> "$RAW_LOG"
echo "Scan Timestamp : $(date)" >> "$RAW_LOG"
echo "--------------------------------------------------" >> "$RAW_LOG"

# 6. Run Custom Python Port Scanner
echo -e "\n[*] Running Custom Python Port Scanner..."
python3 Scanner.py --ip "$TARGET_IP" $PYTHON_PORT | sed 's/\x1B\[[0-9;]*[JKmsu]//g' | tee -a "$RAW_LOG" || {
    echo "[-] Warning: Python scanner encountered an issue, but continuing workflow..." >&2
}
rm -f scan_results.txt

# 7. Run Nmap Vulnerability Scan
echo -e "\n\n[*] Starting Nmap Vulnerability Scan on $TARGET_IP"
echo -e "\n\n==================================================" >> "$RAW_LOG"
echo "         NMAP SERVICE & VULNERABILITY SCAN        " >> "$RAW_LOG"
echo "==================================================" >> "$RAW_LOG"
sudo nmap -sV -O --script=vuln "$TARGET_IP" $NMAP_PORT >> "$RAW_LOG" || {
    echo "[-] Error: Nmap scan failed to execute properly." >&2
    exit 1
}

# 8. Run Nikto Web Vulnerability Assessment
echo -e "\n\n[*] Starting Nikto Web Vulnerability Assessment on $TARGET_IP"
echo -e "\n\n==================================================" >> "$RAW_LOG"
echo "         NIKTO WEB VULNERABILITY ASSESSMENT       " >> "$RAW_LOG"
echo "==================================================" >> "$RAW_LOG"

WEB_PORTS=$(grep -E "open.*(http|ssl|www)" "$RAW_LOG" | awk -F'/' '{print $1}' | tr '\n' ',' | sed 's/,$//')

if [ -z "$WEB_PORTS" ]; then
    if grep -qE "80/tcp.*open|443/tcp.*open" "$RAW_LOG"; then
        WEB_PORTS="80,443"
    fi
fi

if [ -n "$WEB_PORTS" ]; then
    echo "[+] Found active web service(s) on port(s): $WEB_PORTS. Running Nikto..."
    for PORT in $(echo "$WEB_PORTS" | tr ',' ' '); do
        echo "--- NIKTO SCAN RESULTS FOR PORT $PORT ---" >> "$RAW_LOG"
        nikto -h "$TARGET_IP" -p "$PORT" >> "$RAW_LOG" 2>/dev/null || true
    done
else
    echo "[-] No open web ports detected. Skipping Nikto." >> "$RAW_LOG"
    echo "[-] No open web ports detected. Skipping Nikto."
fi

# 9. Generate Final Structured Report
mkdir -p reports
FINAL_REPORT="reports/report.txt"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
ARCHIVE_REPORT="reports/report_${TARGET_IP}_${TIMESTAMP}.txt"

echo "==================================================" > "$FINAL_REPORT"
echo "       AUTOMATED NETWORK SECURITY REPORT          " >> "$FINAL_REPORT"
echo "==================================================" >> "$FINAL_REPORT"
echo "Target IP/Host : $TARGET_IP" >> "$FINAL_REPORT"
echo "Scan Timestamp : $(date)" >> "$FINAL_REPORT"
echo "--------------------------------------------------" >> "$FINAL_REPORT"

# Executive Summary
echo "==================================================" >> "$FINAL_REPORT"
echo "             EXECUTIVE VULNERABILITY SUMMARY      " >> "$FINAL_REPORT"
echo "==================================================" >> "$FINAL_REPORT"
grep "open" "$RAW_LOG" >> "$FINAL_REPORT"
grep "CVE-" "$RAW_LOG" | head -n 15 >> "$FINAL_REPORT"
echo "--------------------------------------------------" >> "$FINAL_REPORT"

# Actionable Remediation Steps
echo -e "\n==================================================" >> "$FINAL_REPORT"
echo "    RECOMMENDED REMEDIATION & MITIGATION STEPS    " >> "$FINAL_REPORT"
echo "==================================================" >> "$FINAL_REPORT"
echo "1. Service Patching: Upgrade outdated services flagged in NSE vulnerability scripts to vendor-recommended stable releases." >> "$FINAL_REPORT"
echo "2. Port Minimization: Close unneeded listening ports identified in the Nmap scan and enforce strict firewall rules." >> "$FINAL_REPORT"
echo "3. Web Hardening: Mitigate directory listings and header disclosures identified via Nikto." >> "$FINAL_REPORT"
echo "--------------------------------------------------" >> "$FINAL_REPORT"

# Full Raw Logs Append
echo -e "\n==================================================" >> "$FINAL_REPORT"
echo "             FULL DETAILED SCAN LOGS              " >> "$FINAL_REPORT"
echo "==================================================" >> "$FINAL_REPORT"
cat "$RAW_LOG" >> "$FINAL_REPORT"

# Archive a copy
cp "$FINAL_REPORT" "$ARCHIVE_REPORT"
rm -f "$RAW_LOG"

echo -e "\n[*] Scan completed successfully!"
echo "[+] Professional report generated: $FINAL_REPORT"
echo "[+] Archived a copy as: $ARCHIVE_REPORT"
```[cite: 1]