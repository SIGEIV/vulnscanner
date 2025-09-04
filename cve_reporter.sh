#!/bin/bash
# Smart Vulnerability Scanner + CVE Reporter
# Author: Sigei (Kali Linux setup)

if [ -z "$1" ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

TARGET=$1
OUTDIR="scan_results_$TARGET"
mkdir -p "$OUTDIR"

echo "[+] Scanning $TARGET, results in $OUTDIR"

# Update Nmap scripts & ExploitDB database
echo "[*] Updating Nmap scripts and ExploitDB..."
nmap --script-updatedb >/dev/null 2>&1
searchsploit -u >/dev/null 2>&1

# --- NMAP Scans ---
echo "[*] Running Nmap service/version scan..."
nmap -sV -T4 "$TARGET" -oN "$OUTDIR/nmap.txt"

echo "[*] Running Nmap vuln + exploit scripts..."
nmap --script vuln,exploit "$TARGET" -oN "$OUTDIR/nmap_vuln_exploit.txt"

# --- Nikto Scan ---
echo "[*] Running Nikto web scan..."
nikto -h "$TARGET" -output "$OUTDIR/nikto.txt"

# --- Gobuster Directory Bruteforce (if HTTP detected) ---
if grep -q "http" "$OUTDIR/nmap.txt"; then
    echo "[*] Running Gobuster on webserver..."
    gobuster dir -u "http://$TARGET" -w /usr/share/wordlists/dirb/common.txt -o "$OUTDIR/gobuster.txt"
fi

# --- Extract CVEs ---
echo "[*] Extracting CVEs from Nmap results..."
grep -Eo "CVE-[0-9]+-[0-9]+" "$OUTDIR/nmap_vuln_exploit.txt" | sort -u > "$OUTDIR/cve_ids.txt"

# --- Generate Detailed CVE Report ---
if [ -s "$OUTDIR/cve_ids.txt" ]; then
    echo "[+] Found CVEs. Fetching details from NVD API..."
    python3 cve_fetcher.py "$OUTDIR/cve_ids.txt" "$OUTDIR/cve_report.txt"
    echo "[+] Detailed CVE report saved to $OUTDIR/cve_report.txt"
else
    echo "[!] No CVEs found in Nmap results."
fi

echo "[✓] Scan complete. Reports saved in $OUTDIR/"
