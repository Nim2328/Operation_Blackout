#!/usr/bin/env python3
"""Offline OSINT correlation tool for Operation Blackout Stage 01."""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "static" / "evidence" / "stage01"


def read_evidence(filename):
    path = EVIDENCE / filename
    if not path.is_file():
        raise FileNotFoundError(f"Missing evidence: {path}")
    return path.read_text(encoding="utf-8")


def require(pattern, text, label, flags=0):
    match = re.search(pattern, text, flags)
    if not match:
        raise ValueError(f"Could not extract {label} from evidence")
    return match


def main():
    incident = read_evidence("incident_note.txt")
    dns = read_evidence("passive_dns.txt")
    cert = read_evidence("certificate_notes.txt")
    registry = read_evidence("asset_registry.txt")

    campaign = require(
        r"Campaign Name:\s*([A-Za-z0-9_-]+)",
        read_evidence("intelligence_brief.txt"),
        "campaign name",
    ).group(1).lower()

    incident_time = require(
        r"At\s+(\d{2}:\d{2})\s+UTC",
        incident,
        "incident time",
    ).group(1)

    records = []
    blocks = re.split(r"\nRecord\s+\d+\s*\n", dns)[1:]

    for block in blocks:
        host = require(
            r"Hostname:\s*([A-Za-z0-9._-]+)", block, "DNS hostname"
        ).group(1)
        ip = require(
            r"Address:\s*((?:\d{1,3}\.){3}\d{1,3})",
            block, "DNS address"
        ).group(1)
        first = require(
            r"First Seen:\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})",
            block, "first-seen time"
        ).group(1)
        last = require(
            r"Last Seen:\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})",
            block, "last-seen time"
        ).group(1)
        queries = int(require(
            r"Observed Queries:\s*(\d+)", block, "query count"
        ).group(1))

        records.append({
            "host": host,
            "ip": ip,
            "first": first,
            "last": last,
            "queries": queries,
        })

    cert_host = require(
        r"Certificate Subject:\s*\nCN=([A-Za-z0-9._-]+)",
        cert, "certificate subject"
    ).group(1)
    cert_ip = require(
        r"Observed IP:\s*((?:\d{1,3}\.){3}\d{1,3})",
        cert, "certificate IP"
    ).group(1)

    print("BLACKOUT STAGE 01 — OFFLINE OSINT CORRELATION")
    print("=" * 48)
    print(f"Campaign: {campaign.upper()}")
    print(f"Incident time: {incident_time} UTC\n")
    print("DNS observations:")

    for record in records:
        print(
            f"- {record['host']} -> {record['ip']} | "
            f"queries={record['queries']} | "
            f"first={record['first']} | last={record['last']}"
        )

    print("\nCertificate correlation:")
    print(f"- Certificate hostname: {cert_host}")
    print(f"- Certificate IP: {cert_ip}")

    matches = [
        r for r in records
        if r["host"] == cert_host and r["ip"] == cert_ip
    ]

    if len(matches) != 1:
        print("RESULT: No unique DNS/TLS match; investigation inconclusive.")
        return 2

    candidate = matches[0]
    incident_stamp = candidate["last"][:10] + " " + incident_time
    active_during_incident = (
        candidate["first"] <= incident_stamp <= candidate["last"]
    )
    sustained_activity = candidate["queries"] >= 100

    print("\nCorrelation checks:")
    print(f"- DNS and certificate hostname/IP match: PASS")
    print(f"- Sustained DNS activity (>=100 queries): "
          f"{'PASS' if sustained_activity else 'FAIL'}")
    print(f"- Active at incident time: "
          f"{'PASS' if active_during_incident else 'FAIL'}")

    if not (sustained_activity and active_during_incident):
        print("RESULT: Candidate does not meet all correlation rules.")
        return 2

    registry_records = re.split(r"\nAsset Record\s+[^\n]+\n", registry)[1:]
    asset = None

    for block in registry_records:
        host_match = re.search(r"Hostname:\s*([A-Za-z0-9._-]+)", block)
        ip_match = re.search(r"Address:\s*((?:\d{1,3}\.){3}\d{1,3})", block)
        role_match = re.search(r"Asset Role:\s*([A-Za-z0-9_-]+)", block)
        status_match = re.search(r"Record Status:\s*([A-Za-z]+)", block)

        if not all((host_match, ip_match, role_match, status_match)):
            continue

        if (host_match.group(1) == candidate["host"]
                and ip_match.group(1) == candidate["ip"]):
            asset = {
                "role": role_match.group(1),
                "status": status_match.group(1).lower(),
            }
            break

    if asset is None:
        print("RESULT: No matching asset registry record.")
        return 2

    corroborated = (
        asset["status"] == "corroborated"
        and asset["role"] != "transient_delivery_indicator"
    )

    print("\nRESULT: Evidence correlation report")
    print(f"Matched hostname: {candidate['host']}")
    print(f"Matched IP: {candidate['ip']}")
    print(f"Campaign identifier: {campaign}")
    print(f"DNS query count: {candidate['queries']}")
    print(f"Observed activity window: {candidate['first']} to {candidate['last']}")
    print(f"Registry role: {asset['role']}")
    print(f"Registry status: {asset['status']}")
    print(f"Registry corroboration: {'PASS' if corroborated else 'FAIL'}")
    print("\nInvestigator conclusion:")
    print("Use the correlated campaign identifier and verified asset role")
    print("to construct the required flag, then submit it through the portal.")
    return 0 if corroborated else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
