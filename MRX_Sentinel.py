#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import platform
import re
import socket
import sqlite3
from collections import Counter
from datetime import datetime
from pathlib import Path


# ============================================================
# MR.X SENTINEL
# SOC & BLUE TEAM ANALYSIS TOOLKIT
# ============================================================

APP_NAME = "MR.X Sentinel"
VERSION = "2.0"

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
REPORT_DIR = DATA_DIR / "reports"
DB_PATH = DATA_DIR / "mrx_soc.db"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
WHITE = "\033[97m"
GRAY = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"


# ============================================================
# REGEX
# ============================================================

IP_PATTERN = re.compile(
    r"(?<![\d.])"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"(?![\d.])"
)

DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[A-Za-z]{2,63}\b"
)

URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>]+",
    re.I
)

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@"
    r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

HASH_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{32}\b"
    r"|\b[a-fA-F0-9]{40}\b"
    r"|\b[a-fA-F0-9]{64}\b"
)


POWERSHELL_RULES = [
    r"\bEncodedCommand\b",
    r"\s-enc(?:odedcommand)?\b",
    r"FromBase64String",
    r"DownloadString",
    r"Invoke-WebRequest",
    r"\bIEX\b",
    r"Invoke-Expression",
    r"Net\.WebClient",
    r"ExecutionPolicy\s+Bypass",
]


MITRE_RULES = [
    (
        re.compile(
            r"EncodedCommand|-enc\b|"
            r"FromBase64String",
            re.I,
        ),
        "T1059.001",
        "PowerShell",
    ),

    (
        re.compile(
            r"DownloadString|"
            r"Invoke-WebRequest|"
            r"Net\.WebClient",
            re.I,
        ),
        "T1105",
        "Ingress Tool Transfer",
    ),

    (
        re.compile(
            r"4625|failed logon|"
            r"failed login|"
            r"authentication failure",
            re.I,
        ),
        "T1110",
        "Brute Force",
    ),

    (
        re.compile(
            r"4720|new user|"
            r"account created",
            re.I,
        ),
        "T1136.001",
        "Create Account: Local Account",
    ),

    (
        re.compile(
            r"4698|scheduled task",
            re.I,
        ),
        "T1053.005",
        "Scheduled Task",
    ),

    (
        re.compile(
            r"4728|4732|added to.*group",
            re.I,
        ),
        "T1098",
        "Account Manipulation",
    ),
]


# ============================================================
# FILESYSTEM
# ============================================================

def ensure_dirs():

    DATA_DIR.mkdir(exist_ok=True)
    REPORT_DIR.mkdir(exist_ok=True)


# ============================================================
# DATABASE
# ============================================================

def init_db():

    ensure_dirs()

    with sqlite3.connect(DB_PATH) as db:

        db.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                severity TEXT NOT NULL,
                rule TEXT NOT NULL,
                evidence TEXT,
                source TEXT
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT,
                ioc TEXT,
                mitre TEXT,
                status TEXT NOT NULL,
                notes TEXT
            )
        """)

        db.commit()


def save_alert(
    severity,
    rule,
    evidence,
    source="",
):

    with sqlite3.connect(DB_PATH) as db:

        db.execute(
            """
            INSERT INTO alerts
            (
                created_at,
                severity,
                rule,
                evidence,
                source
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                datetime.now().isoformat(
                    timespec="seconds"
                ),
                severity,
                rule,
                evidence[:4000],
                source,
            ),
        )

        db.commit()


# ============================================================
# UI
# ============================================================

def clear():

    os.system(
        "cls"
        if os.name == "nt"
        else "clear"
    )


def banner():

    print(
        RED
        + BOLD
        + r"""
███╗   ███╗██████╗       ██╗  ██╗
████╗ ████║██╔══██╗      ╚██╗██╔╝
██╔████╔██║██████╔╝█████╗ ╚███╔╝
██║╚██╔╝██║██╔═══╝ ╚════╝ ██╔██╗
██║ ╚═╝ ██║██║           ██╔╝ ██╗
╚═╝     ╚═╝╚═╝           ╚═╝  ╚═╝
"""
        + RESET
    )

    print(
        CYAN
        + f"       {APP_NAME} v{VERSION}"
        + RESET
    )

    print(
        GRAY
        + "       SOC / BLUE TEAM DEFENSIVE TOOLKIT"
        + RESET
    )

    print()


# ============================================================
# IOC ANALYSIS
# ============================================================

def classify_ip(ip):

    try:

        obj = ipaddress.ip_address(ip)

        if obj.is_private:
            return "PRIVATE"

        if obj.is_loopback:
            return "LOOPBACK"

        if obj.is_reserved:
            return "RESERVED"

        if obj.is_link_local:
            return "LINK-LOCAL"

        return "PUBLIC"

    except ValueError:

        return "INVALID"


def extract_iocs(text):

    ips = set()
    domains = set()
    urls = set()
    emails = set()
    hashes = set()

    for raw in IP_PATTERN.findall(text):

        if classify_ip(raw) != "INVALID":

            ips.add(raw)

    for value in DOMAIN_PATTERN.findall(text):

        domains.add(value.lower())

    for value in URL_PATTERN.findall(text):

        urls.add(value.rstrip(".,;"))

    for value in EMAIL_PATTERN.findall(text):

        emails.add(value.lower())

    for value in HASH_PATTERN.findall(text):

        hashes.add(value.lower())

    return {
        "ips": sorted(ips),
        "domains": sorted(domains),
        "urls": sorted(urls),
        "emails": sorted(emails),
        "hashes": sorted(hashes),
    }


# ============================================================
# MITRE
# ============================================================

def mitre_mapping(text):

    results = []

    for pattern, technique, name in MITRE_RULES:

        if pattern.search(text):

            results.append(
                {
                    "technique": technique,
                    "name": name,
                }
            )

    return results


# ============================================================
# POWERSHELL DETECTION
# ============================================================

def detect_powershell(text):

    matches = []

    for rule in POWERSHELL_RULES:

        if re.search(
            rule,
            text,
            re.I,
        ):

            matches.append(rule)

    return matches


# ============================================================
# IOC ANALYZER
# ============================================================

def ioc_analyzer():

    print(
        CYAN
        + "\n=== MR.X IOC ANALYZER ==="
        + RESET
    )

    print(
        "Paste IOC/text data."
    )

    print(
        GRAY
        + "Finish with Ctrl+Z then Enter."
        + RESET
    )

    lines = []

    while True:

        try:

            lines.append(input())

        except EOFError:

            break

    text = "\n".join(lines)

    if not text.strip():

        print(
            YELLOW
            + "No data supplied."
            + RESET
        )

        return

    iocs = extract_iocs(text)

    print(
        CYAN
        + "\n[ IOC RESULTS ]"
        + RESET
    )

    for category, values in iocs.items():

        print(
            f"\n{category.upper()}:"
        )

        if not values:

            print("  -")

            continue

        for value in values:

            if category == "ips":

                print(
                    f"  {value:16} "
                    f"[{classify_ip(value)}]"
                )

            else:

                print(
                    f"  {value}"
                )

    powershell = detect_powershell(text)

    print(
        CYAN
        + "\n[ DETECTION ]"
        + RESET
    )

    if powershell:

        print(
            RED
            + "[HIGH] Suspicious PowerShell detected"
            + RESET
        )

        save_alert(
            "HIGH",
            "Suspicious PowerShell",
            text,
            "IOC Analyzer",
        )

    else:

        print(
            GREEN
            + "No suspicious PowerShell detected."
            + RESET
        )

    mappings = mitre_mapping(text)

    print(
        CYAN
        + "\n[ MITRE ATT&CK ]"
        + RESET
    )

    if mappings:

        for mapping in mappings:

            print(
                f"  {mapping['technique']} - "
                f"{mapping['name']}"
            )

    else:

        print("  -")


# ============================================================
# LOG ANALYZER
# ============================================================

def analyze_lines(
    lines,
    source="",
):

    alerts = []

    failed_by_ip = Counter()

    for line_number, line in enumerate(
        lines,
        1,
    ):

        low = line.lower()

        # ----------------------------------------------------
        # FAILED AUTH
        # ----------------------------------------------------

        failed_event = (
            "4625" in line
            or "failed logon" in low
            or "failed login" in low
            or "authentication failure" in low
        )

        if failed_event:

            for ip in IP_PATTERN.findall(line):

                if classify_ip(ip) == "PUBLIC":

                    failed_by_ip[ip] += 1

        # ----------------------------------------------------
        # POWERSHELL
        # ----------------------------------------------------

        if detect_powershell(line):

            alert = {
                "severity": "HIGH",
                "rule": "Suspicious PowerShell",
                "line": line_number,
                "evidence": line.strip(),
                "mitre": mitre_mapping(line),
            }

            alerts.append(alert)

            save_alert(
                "HIGH",
                "Suspicious PowerShell",
                line.strip(),
                source,
            )

        # ----------------------------------------------------
        # ACCOUNT CREATION
        # ----------------------------------------------------

        if re.search(
            r"4720|new user|account created",
            line,
            re.I,
        ):

            alert = {
                "severity": "MEDIUM",
                "rule": "Possible Account Creation",
                "line": line_number,
                "evidence": line.strip(),
                "mitre": mitre_mapping(line),
            }

            alerts.append(alert)

            save_alert(
                "MEDIUM",
                "Possible Account Creation",
                line.strip(),
                source,
            )

        # ----------------------------------------------------
        # SCHEDULED TASK
        # ----------------------------------------------------

        if re.search(
            r"4698|scheduled task",
            line,
            re.I,
        ):

            alert = {
                "severity": "HIGH",
                "rule":
                    "Possible Scheduled Task Persistence",
                "line": line_number,
                "evidence": line.strip(),
                "mitre": mitre_mapping(line),
            }

            alerts.append(alert)

            save_alert(
                "HIGH",
                "Possible Scheduled Task Persistence",
                line.strip(),
                source,
            )

    # --------------------------------------------------------
    # BRUTE FORCE
    # --------------------------------------------------------

    for ip, count in failed_by_ip.items():

        if count >= 5:

            evidence = (
                f"{count} failed authentication "
                f"events from {ip}"
            )

            alert = {
                "severity": "HIGH",
                "rule": "Possible Brute Force",
                "line": "-",
                "evidence": evidence,
                "mitre": [
                    {
                        "technique": "T1110",
                        "name": "Brute Force",
                    }
                ],
            }

            alerts.append(alert)

            save_alert(
                "HIGH",
                "Possible Brute Force",
                evidence,
                source,
            )

    text = "\n".join(lines)

    return {
        "source": source,
        "lines": len(lines),
        "alerts": alerts,
        "iocs": extract_iocs(text),
        "mitre": mitre_mapping(text),
        "failed_auth_sources":
            dict(failed_by_ip),
    }


# ============================================================
# DISPLAY LOG RESULTS
# ============================================================

def print_analysis(result):

    print(
        CYAN
        + "\n=== LOG ANALYSIS ==="
        + RESET
    )

    print(
        f"Source : {result['source']}"
    )

    print(
        f"Lines  : {result['lines']}"
    )

    print(
        f"Alerts : {len(result['alerts'])}"
    )

    print(
        YELLOW
        + "\n[ ALERTS ]"
        + RESET
    )

    if not result["alerts"]:

        print(
            GREEN
            + "No alerts."
            + RESET
        )

    else:

        for index, alert in enumerate(
            result["alerts"],
            1,
        ):

            print(
                RED
                + f"{index:02d}. "
                + f"[{alert['severity']}] "
                + f"{alert['rule']}"
                + RESET
            )

            print(
                f"    Line    : "
                f"{alert['line']}"
            )

            print(
                f"    Evidence: "
                f"{alert['evidence']}"
            )

            if alert["mitre"]:

                print(
                    "    MITRE   : "
                    + ", ".join(
                        f"{x['technique']} "
                        f"({x['name']})"
                        for x in alert["mitre"]
                    )
                )

    print(
        CYAN
        + "\n[ IOCS ]"
        + RESET
    )

    for category, values in result["iocs"].items():

        print(
            f"{category.upper():8}: "
            f"{', '.join(values) if values else '-'}"
        )


# ============================================================
# FILE ANALYZER
# ============================================================

def analyze_file(path):

    path = Path(path)

    if not path.exists():

        print(
            RED
            + "File not found."
            + RESET
        )

        return

    try:

        lines = path.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()

    except OSError as exc:

        print(
            RED
            + f"Read error: {exc}"
            + RESET
        )

        return

    result = analyze_lines(
        lines,
        str(path),
    )

    print_analysis(result)

    export = input(
        "\nExport JSON report? [y/N]: "
    ).strip().lower()

    if export == "y":

        stamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        output = (
            REPORT_DIR
            / f"mrx_report_{stamp}.json"
        )

        output.write_text(
            json.dumps(
                result,
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        print(
            GREEN
            + f"Report saved: {output}"
            + RESET
        )


# ============================================================
# DASHBOARD
# ============================================================

def dashboard():

    with sqlite3.connect(DB_PATH) as db:

        total = db.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        rows = db.execute(
            """
            SELECT severity, COUNT(*)
            FROM alerts
            GROUP BY severity
            """
        ).fetchall()

        incidents = db.execute(
            "SELECT COUNT(*) FROM incidents"
        ).fetchone()[0]

    counts = dict(rows)

    print(
        CYAN
        + "\n=== SOC DASHBOARD ==="
        + RESET
    )

    print(
        f"Total Alerts : {total}"
    )

    print(
        f"Critical     : "
        f"{counts.get('CRITICAL', 0)}"
    )

    print(
        f"High         : "
        f"{counts.get('HIGH', 0)}"
    )

    print(
        f"Medium       : "
        f"{counts.get('MEDIUM', 0)}"
    )

    print(
        f"Low          : "
        f"{counts.get('LOW', 0)}"
    )

    print(
        f"Incidents    : {incidents}"
    )

    print(
        f"Database     : {DB_PATH}"
    )


# ============================================================
# SYSTEM INFO
# ============================================================

def system_info():

    print(
        CYAN
        + "\n=== SYSTEM INFORMATION ==="
        + RESET
    )

    print(
        f"OS          : "
        f"{platform.system()} "
        f"{platform.release()}"
    )

    print(
        f"Platform    : "
        f"{platform.platform()}"
    )

    print(
        f"Python      : "
        f"{platform.python_version()}"
    )

    print(
        f"Hostname    : "
        f"{socket.gethostname()}"
    )

    print(
        f"Architecture: "
        f"{platform.machine()}"
    )


# ============================================================
# NETWORK INFO
# ============================================================

def network_info():

    print(
        CYAN
        + "\n=== NETWORK INFORMATION ==="
        + RESET
    )

    hostname = socket.gethostname()

    print(
        f"Hostname: {hostname}"
    )

    try:

        addresses = socket.gethostbyname_ex(
            hostname
        )[2]

        for ip in addresses:

            print(
                f"IP      : {ip}"
            )

    except socket.error as exc:

        print(
            f"IP      : unavailable ({exc})"
        )


# ============================================================
# INCIDENT
# ============================================================

def create_incident():

    print(
        CYAN
        + "\n=== CREATE INCIDENT ==="
        + RESET
    )

    title = input(
        "Title: "
    ).strip()

    if not title:

        print(
            RED
            + "Title required."
            + RESET
        )

        return

    severity = input(
        "Severity [LOW/MEDIUM/HIGH/CRITICAL]: "
    ).strip().upper()

    if severity not in (
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    ):

        severity = "MEDIUM"

    source = input(
        "Source: "
    ).strip()

    ioc = input(
        "IOC: "
    ).strip()

    mitre = input(
        "MITRE: "
    ).strip()

    notes = input(
        "Notes: "
    ).strip()

    with sqlite3.connect(DB_PATH) as db:

        db.execute(
            """
            INSERT INTO incidents
            (
                created_at,
                title,
                severity,
                source,
                ioc,
                mitre,
                status,
                notes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now().isoformat(
                    timespec="seconds"
                ),
                title,
                severity,
                source,
                ioc,
                mitre,
                "OPEN",
                notes,
            ),
        )

        db.commit()

    print(
        GREEN
        + "Incident created."
        + RESET
    )


# ============================================================
# INCIDENT LIST
# ============================================================

def list_incidents():

    with sqlite3.connect(DB_PATH) as db:

        rows = db.execute(
            """
            SELECT
                id,
                created_at,
                title,
                severity,
                status,
                source
            FROM incidents
            ORDER BY id DESC
            """
        ).fetchall()

    print(
        CYAN
        + "\n=== INCIDENTS ==="
        + RESET
    )

    if not rows:

        print("- No incidents.")

        return

    for row in rows:

        print(
            f"#{row[0]} "
            f"[{row[3]}] "
            f"{row[2]} | "
            f"{row[4]} | "
            f"{row[5] or '-'} | "
            f"{row[1]}"
        )


# ============================================================
# INTERACTIVE
# ============================================================

def interactive():

    while True:

        clear()
        banner()

        print("""
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
""")

        choice = input(
            RED
            + "MR.X >>> "
            + RESET
        ).strip()

        if choice == "1":

            dashboard()

        elif choice == "2":

            path = input(
                "Log file path: "
            ).strip()

            analyze_file(path)

        elif choice == "3":

            ioc_analyzer()

        elif choice == "4":

            text = input(
                "Paste evidence: "
            )

            mappings = mitre_mapping(text)

            if mappings:

                for mapping in mappings:

                    print(
                        f"{mapping['technique']} - "
                        f"{mapping['name']}"
                    )

            else:

                print(
                    "No MITRE rule matched."
                )

        elif choice == "5":

            create_incident()

        elif choice == "6":

            network_info()

        elif choice == "7":

            system_info()

        elif choice == "8":

            list_incidents()

        elif choice == "9":

            print(
                "\nMR.X Sentinel"
            )

            print(
                "SOC / Blue Team defensive "
                "analysis toolkit."
            )

        elif choice == "0":

            print(
                GREEN
                + "\nMR.X session closed."
                + RESET
            )

            break

        else:

            print(
                RED
                + "Unknown command."
                + RESET
            )

        input(
            "\nPress Enter to continue..."
        )


# ============================================================
# CLI
# ============================================================

def main():

    init_db()

    parser = argparse.ArgumentParser(
        description=
        "MR.X Sentinel SOC Toolkit"
    )

    sub = parser.add_subparsers(
        dest="command"
    )

    analyze = sub.add_parser(
        "analyze",
        help="Analyze log file",
    )

    analyze.add_argument(
        "file"
    )

    sub.add_parser("dashboard")
    sub.add_parser("system")
    sub.add_parser("network")
    sub.add_parser("incidents")

    args = parser.parse_args()

    if args.command == "analyze":

        analyze_file(args.file)

    elif args.command == "dashboard":

        dashboard()

    elif args.command == "system":

        system_info()

    elif args.command == "network":

        network_info()

    elif args.command == "incidents":

        list_incidents()

    else:

        interactive()


if __name__ == "__main__":

    main()