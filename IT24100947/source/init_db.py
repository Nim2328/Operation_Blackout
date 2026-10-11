import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import hashlib

from app import create_app
from database.models import db, Stage


STAGES = [
    {
        "stage_number": 1,
        "name": "OSINT",
        "domain": "INTELLIGENCE",
        "description": "Identify the external infrastructure connected to the BLACKOUT incident.",
        "points": 100,
        "flag": "FLAG{ar_014_nf_2026_0910_27}",
    },
    {
        "stage_number": 2,
        "name": "STEGANOGRAPHY",
        "domain": "DIGITAL FORENSICS",
        "description": "Recover hidden information from the suspicious image discovered during the investigation.",
        "points": 100,
        "flag": "FLAG{hidden_client_transfer}",
    },
    {
        "stage_number": 3,
        "name": "CRYPTOGRAPHY",
        "domain": "CRYPTOGRAPHY",
        "description": "Decrypt the recovered communication and identify the compromised workstation.",
        "points": 100,
        "flag": "FLAG{ops_ws_17}",
    },
    {
        "stage_number": 4,
        "name": "DIGITAL FORENSICS",
        "domain": "DIGITAL FORENSICS",
        "description": "Analyse host evidence and identify the persistence mechanism used by the attacker.",
        "points": 100,
        "flag": "FLAG{update_service}",
    },
    {
        "stage_number": 5,
        "name": "NETWORK ANALYSIS",
        "domain": "NETWORK SECURITY",
        "description": "Analyse captured network traffic and identify the command-and-control activity.",
        "points": 100,
        "flag": "FLAG{blackout_c2}",
    },
    {
        "stage_number": 6,
        "name": "MEMORY FORENSICS",
        "domain": "MEMORY ANALYSIS",
        "description": "Investigate volatile memory and identify the malicious process.",
        "points": 100,
        "flag": "FLAG{malware_loader}",
    },
    {
        "stage_number": 7,
        "name": "PRIVILEGE ESCALATION",
        "domain": "LINUX SECURITY",
        "description": "Determine how the attacker obtained elevated privileges on the compromised system.",
        "points": 100,
        "flag": "FLAG{blackout_priv_07}",
    },
    {
        "stage_number": 8,
        "name": "REVERSE ENGINEERING",
        "domain": "BINARY ANALYSIS",
        "description": "Analyse the recovered executable and determine the attacker's final objective.",
        "points": 100,
        "flag": "FLAG{blackout_final_08}",
    },
]


def hash_flag(flag):
    return hashlib.sha256(flag.encode()).hexdigest()


app = create_app()

with app.app_context():

    db.create_all()

    for stage_data in STAGES:

        existing = Stage.query.filter_by(
            stage_number=stage_data["stage_number"]
        ).first()

        if existing:
            print(
                f"Stage {stage_data['stage_number']:02d} already exists"
            )
            continue

        stage = Stage(
            stage_number=stage_data["stage_number"],
            name=stage_data["name"],
            domain=stage_data["domain"],
            description=stage_data["description"],
            points=stage_data["points"],
            flag_hash=hash_flag(stage_data["flag"]),
        )

        db.session.add(stage)

        print(
            f"Added Stage {stage_data['stage_number']:02d}: "
            f"{stage_data['name']}"
        )

    db.session.commit()

    print()
    print("Operation Blackout stage database initialized.")
