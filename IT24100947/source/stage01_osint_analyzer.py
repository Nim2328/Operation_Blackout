#!/usr/bin/env python3

from pathlib import Path
from datetime import datetime
import re
import sys

BASE = Path(__file__).resolve().parents[1]
EVIDENCE = BASE / "static" / "evidence" / "stage01"

def read_evidence(filename):
    path = EVIDENCE / filename
    if not path.is_file():
        raise FileNotFoundError(f"Evidence file missing: {path}")
    return path.read_text(encoding="utf-8", errors="replace")

def extract_dns_records(text):
    records = []
    blocks = re.split(r"(?im)^\s*Record\s+\d+\s*$", text)

    for block in blocks:
        host = re.search(
            r"(?im)^\s*Hostname\s*:\s*(\S+)", block
        )
        address = re.search(
            r"(?im)^\s*Address\s*:\s*((?:\d{1,3}\.){3}\d{1,3})",
            block
        )
        first = re.search(
            r"(?im)^\s*First Seen\s*:\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})",
            block
        )
        last = re.search(
            r"(?im)^\s*Last Seen\s*:\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})",
            block
        )
        queries = re.search(
            r"(?im)^\s*Observed Queries\s*:\s*(\d+)",
            block
        )

        if not all((host, address, first, last, queries)):
            continue

        try:
            first_time = datetime.strptime(
                first.group(1), "%Y-%m-%d %H:%M"
            )
            last_time = datetime.strptime(
                last.group(1), "%Y-%m-%d %H:%M"
            )
        except ValueError:
            continue

        duration = int(
            (last_time - first_time).total_seconds() / 60
        )
        if duration < 0:
            continue

        records.append({
            "hostname": host.group(1).lower(),
            "ip": address.group(1),
            "queries": int(queries.group(1)),
            "duration": duration,
        })

    return records

def extract_certificate(text):
    cn = re.search(
        r"(?im)^\s*CN\s*=\s*([a-zA-Z0-9.-]+)", text
    )
    ip = re.search(
        r"(?im)^\s*Observed IP\s*:\s*((?:\d{1,3}\.){3}\d{1,3})",
        text
    )
    return {
        "hostname": cn.group(1).lower() if cn else None,
        "ip": ip.group(1) if ip else None,
    }

def derive_candidate_flag(hostname):
    # Challenge-specific naming convention:
    # <name>-update.example -> FLAG{<name>_infrastructure}
    match = re.fullmatch(
        r"([a-z0-9]+)-update\.example", hostname, re.IGNORECASE
    )
    if not match:
        return None
    return f"FLAG{{{match.group(1).lower()}_infrastructure}}"

def main():
    print("=== BLACKOUT OSINT INVESTIGATION ===\n")

    try:
        incident = read_evidence("incident_note.txt")
        dns_text = read_evidence("passive_dns.txt")
        cert_text = read_evidence("certificate_notes.txt")
    except OSError as error:
        print(f"[ERROR] {error}")
        sys.exit(1)

    records = extract_dns_records(dns_text)
    certificate = extract_certificate(cert_text)

    if not records:
        print("[ERROR] Could not parse passive DNS records.")
        print("Check the Hostname, Address, First Seen,")
        print("Last Seen and Observed Queries fields.")
        sys.exit(1)

    for record in records:
        record["certificate_match"] = (
            record["hostname"] == certificate["hostname"]
            and record["ip"] == certificate["ip"]
            and certificate["hostname"] is not None
            and certificate["ip"] is not None
        )

    records.sort(
        key=lambda r: (
            r["certificate_match"], r["queries"], r["duration"]
        ),
        reverse=True,
    )

    print("=== TLS CERTIFICATE ===")
    print(f"Hostname: {certificate['hostname']}")
    print(f"IP address: {certificate['ip']}\n")

    print("=== PASSIVE DNS FINDINGS ===\n")
    for record in records:
        print(f"Hostname: {record['hostname']}")
        print(f"IP address: {record['ip']}")
        print(f"DNS queries: {record['queries']}")
        print(f"Active duration: {record['duration']} minutes")
        print(f"Certificate match: {record['certificate_match']}\n")

    primary = records[0]
    print("=== OSINT CONCLUSION ===")
    print(f"Primary endpoint: {primary['hostname']}")
    print(f"Associated IP: {primary['ip']}")
    print(f"NIGHTFALL mentioned in incident: {'nightfall' in incident.lower()}")

    print("\nSupporting evidence:")
    print(f"- DNS query count: {primary['queries']}")
    print(f"- Activity duration: {primary['duration']} minutes")
    print(f"- TLS certificate match: {primary['certificate_match']}")

    candidate = derive_candidate_flag(primary["hostname"])
    print("\n=== CTF FLAG CANDIDATE ===")
    if candidate:
        print(f"Candidate: {candidate}")
        print("Derived from the primary hostname using the configured")
        print("CTF naming convention. Submit it in the CTF interface.")
    else:
        print("No candidate matches the configured naming convention.")

if __name__ == "__main__":
    main()
