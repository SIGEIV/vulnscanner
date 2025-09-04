🔹 VulnScanner – Smart Automated Vulnerability Scanner

VulnScanner is a Bash + Python hybrid tool built for Kali Linux that automates web and service vulnerability discovery, CVE enrichment, and exploitability checks.

It combines well-known security tools (nmap, nikto, gobuster, searchsploit) with the NVD API (nvdlib) to generate a professional vulnerability report.

✨ Features

🔍 Network & Service Scanning
Uses Nmap to fingerprint open ports, detect services, and run vulnerability scripts.

🌐 Web Vulnerability Testing
Uses Nikto to scan for common web server misconfigurations and security issues.

📂 Directory Discovery
Runs Gobuster against HTTP services to enumerate hidden files/folders.

🛡️ CVE Extraction & Enrichment
Pulls CVEs from Nmap scan results, then uses NVD API (nvdlib) to fetch:

CVSS base scores

Severity levels (LOW, MEDIUM, HIGH, CRITICAL)

CWE IDs (weakness classification)

Vulnerability descriptions

Suggested remediation

💣 Exploitability Check
Cross-references CVEs with ExploitDB (searchsploit) and known Metasploit modules to check if public exploits exist.

📑 Detailed Reporting
Generates a structured text report including:

Scanned target summary

Found services and vulnerabilities

CVE details sorted by severity

Exploitability status (with ExploitDB/Metasploit links if found)

Remediation guidance

⏳ Rate-limited API calls
Automatically sleeps between NVD API calls to avoid rate-limit errors.

🛠 Requirements

Make sure these packages are installed:

sudo apt update && sudo apt install -y nmap nikto gobuster exploitdb python3-pip jq
pip3 install nvdlib

📂 File Structure

Your project looks like this:

~/vulnscanner/
├── cve_reporter.sh     # Bash wrapper script
├── cve_fetcher.py      # Python CVE enrichment script
└── scan_results_<target>/  # Auto-created per scan
    ├── nmap.txt
    ├── nmap_vuln_exploit.txt
    ├── nikto.txt
    ├── gobuster.txt
    ├── cve_ids.txt
    └── cve_report.txt

🚀 Usage

Make scripts executable:

chmod +x cve_reporter.sh cve_fetcher.py


Run the scanner against a target:

./cve_reporter.sh testphp.vulnweb.com


Review results inside the scan_results_<target>/ folder.
The final CVE report will be in:

scan_results_<target>/cve_report.txt

📑 Example CVE Report (sample output)
==============================
CVE: CVE-2022-12345
Severity: HIGH
CVSS Score: 7.8
CWE: CWE-79 (Cross-Site Scripting)
Description: Vulnerability in XYZ service allows remote attackers to inject code.
Exploit Status: Public exploit available (ExploitDB: 12345, Metasploit: exploit/multi/http/xyz)
Remediation: Update XYZ to version 2.3.4 or later. Apply vendor patches.
==============================

CVE: CVE-2021-6789
Severity: CRITICAL
CVSS Score: 9.8
CWE: CWE-89 (SQL Injection)
Description: SQL Injection in ABC web app login page.
Exploit Status: No public exploit found. Potential 0-day.
Remediation: Use parameterized queries, sanitize inputs, apply vendor patch.
==============================

⚠️ Legal Disclaimer

This tool is for educational purposes and authorized penetration testing only.
Do not scan networks or systems without explicit written permission.
