#!/usr/bin/env python3
import sys, time, json, subprocess
import nvdlib

# --- CWE → readable name ---
CWE_MAP = {
    "CWE-22": "Path Traversal",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-200": "Information Exposure",
    "CWE-287": "Improper Authentication",
    "CWE-352": "CSRF",
}

# --- CWE → remediation ---
REMEDIATION_MAP = {
    "CWE-22": "Validate and sanitize file paths; enforce strict whitelists.",
    "CWE-79": "Use output encoding, input sanitization, and CSP headers.",
    "CWE-89": "Use parameterized queries, ORM frameworks, and strict input validation.",
    "CWE-200": "Apply access controls; minimize sensitive data exposure.",
    "CWE-287": "Enforce MFA, session hardening, and secure credential storage.",
    "CWE-352": "Implement anti-CSRF tokens, same-site cookies, and referrer checks.",
}

# --- Severity flag ---
def severity_flag(score):
    if score == "N/A":
        return "⚪ Unknown"
    score = float(score)
    if score >= 9.0:
        return "🔴 Critical"
    elif score >= 7.0:
        return "🟠 High"
    elif score >= 4.0:
        return "🟡 Medium"
    else:
        return "🟢 Low"

# --- Priority calc ---
def priority(score, asset_types):
    if score == "N/A":
        return "Low"
    s = float(score)
    if "Web Server" in asset_types and s >= 7.0:
        return "Critical"
    if s >= 9.0:
        return "Critical"
    elif s >= 7.0:
        return "High"
    elif s >= 4.0:
        return "Medium"
    else:
        return "Low"

# --- ExploitDB check ---
def check_exploitdb(cve):
    try:
        output = subprocess.check_output(["searchsploit", "--nmap", cve], stderr=subprocess.DEVNULL)
        if output.strip():
            return True
    except Exception:
        pass
    return False

# --- Metasploit check ---
def check_metasploit(cve):
    try:
        cmd = f"msfconsole -q -x 'search {cve}; exit'"
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=20).decode()
        if "exploit/" in output:
            return True
    except Exception:
        pass
    return False

def fetch_cve_details(cve_list_file, nmap_file, output_basename):
    # --- Asset detection from Nmap ---
    def detect_asset():
        asset_types = []
        with open(nmap_file, "r") as f:
            data = f.read().lower()
            if "http" in data: asset_types.append("Web Server")
            if "ftp" in data: asset_types.append("FTP Server")
            if "mysql" in data or "postgres" in data: asset_types.append("Database")
            if "ssh" in data: asset_types.append("Remote Access (SSH)")
            if "rdp" in data: asset_types.append("Remote Desktop")
            if "smtp" in data: asset_types.append("Mail Server")
        return asset_types if asset_types else ["Generic Host"]

    asset_types = detect_asset()

    with open(cve_list_file, "r") as f:
        cves = [line.strip() for line in f if line.strip()]

    report_entries = []

    for cve in cves:
        print(f"[+] Fetching {cve} from NVD...")
        results = nvdlib.searchCVE(cveId=cve)
        if not results:
            continue

        cve_data = results[0]

        desc = cve_data.descriptions[0].value if cve_data.descriptions else "No description"
        cwe = cve_data.cwes[0].cweId if cve_data.cwes else "N/A"
        cwe_name = CWE_MAP.get(cwe, "Unknown Weakness")
        remediation = REMEDIATION_MAP.get(cwe, "Apply vendor patches and general hardening.")

        score, severity = "N/A", "N/A"
        if cve_data.metrics:
            cvss_v3 = cve_data.metrics.get("cvssMetricV31") or cve_data.metrics.get("cvssMetricV30")
            if cvss_v3:
                cvss = cvss_v3[0].cvssData
                score = cvss.baseScore
                severity = cvss.baseSeverity

        # --- Exploitability checks ---
        exploitdb = check_exploitdb(cve)
        metasploit = check_metasploit(cve)
        if exploitdb or metasploit:
            exploit_status = f"✅ Exploit Available ({'ExploitDB' if exploitdb else ''}{' + ' if exploitdb and metasploit else ''}{'Metasploit' if metasploit else ''})"
        else:
            exploit_status = "❌ No public exploit known"

        entry = {
            "cve": cve,
            "description": desc,
            "cwe": cwe,
            "cwe_name": cwe_name,
            "cvss_score": score,
            "severity": severity,
            "severity_flag": severity_flag(score),
            "remediation": remediation,
            "asset_types": asset_types,
            "priority": priority(score, asset_types),
            "exploit_status": exploit_status,
            "references": {
                "NVD": f"https://nvd.nist.gov/vuln/detail/{cve}",
                "CWE": f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html" if "CWE-" in cwe else "N/A"
            }
        }
        report_entries.append(entry)

        # Rate-limit API calls
        time.sleep(6)

    # Sort by score descending
    report_entries.sort(key=lambda x: 0 if x["cvss_score"]=="N/A" else float(x["cvss_score"]), reverse=True)

    # Save TXT
    with open(f"{output_basename}.txt", "w") as txt:
        for e in report_entries:
            txt.write(f"""
====================================================
Submit Vulnerability Report
====================================================
1. Asset
Target: {", ".join(e['asset_types'])}

2. Weakness
Type: {e['cwe']} - {e['cwe_name']}

3. Vulnerability Details
CVE: {e['cve']}
Description: {e['description']}
CVSS Score: {e['cvss_score']} ({e['severity_flag']})
Severity: {e['severity']}
Priority: {e['priority']}
Exploitability: {e['exploit_status']}

4. Remediation Guidance
{e['remediation']}

5. References
NVD: {e['references']['NVD']}
CWE: {e['references']['CWE']}

----------------------------------------------------
""")

    # Save JSON
    with open(f"{output_basename}.json", "w") as js:
        json.dump(report_entries, js, indent=4)

    print(f"[+] Reports written to {output_basename}.txt and {output_basename}.json")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 cve_fetcher.py <cve_ids.txt> <nmap.txt> <output_basename>")
        sys.exit(1)

    fetch_cve_details(sys.argv[1], sys.argv[2], sys.argv[3])
