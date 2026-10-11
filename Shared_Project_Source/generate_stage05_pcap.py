from scapy.all import IP, UDP, TCP, DNS, DNSQR, DNSRR, Raw, wrpcap
from pathlib import Path
from datetime import datetime, timedelta

OUT = Path("static/evidence/stage05/network_capture.pcap")

CLIENT = "192.168.10.25"
DNS_SERVER = "192.168.10.1"
INTERNAL_WEB = "192.168.10.10"
C2_IP = "10.20.30.50"

C2_DOMAIN = "cdn-sync.blackout-update.net"

START = datetime(2026, 8, 19, 9, 14, 0)

packets = []


def add_time(packet, seconds):
    packet.time = (START + timedelta(seconds=seconds)).timestamp()
    packets.append(packet)


def tcp_packet(src, dst, sport, dport, payload=b"", flags="PA"):
    return (
        IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags=flags)
        / Raw(load=payload)
    )


# ============================================================
# 1. NORMAL DNS TRAFFIC
# ============================================================

normal_dns = [
    ("intranet.blackout.local", INTERNAL_WEB),
    ("files.blackout.local", INTERNAL_WEB),
    ("updates.blackout.local", INTERNAL_WEB),
    ("mail.blackout.local", INTERNAL_WEB),
]

for i, (domain, answer) in enumerate(normal_dns):
    sport = 53000 + i

    query = (
        IP(src=CLIENT, dst=DNS_SERVER)
        / UDP(sport=sport, dport=53)
        / DNS(
            id=100 + i,
            qr=0,
            rd=1,
            qd=DNSQR(qname=domain)
        )
    )

    response = (
        IP(src=DNS_SERVER, dst=CLIENT)
        / UDP(sport=53, dport=sport)
        / DNS(
            id=100 + i,
            qr=1,
            rd=1,
            ra=1,
            qd=DNSQR(qname=domain),
            an=DNSRR(
                rrname=domain,
                type="A",
                ttl=300,
                rdata=answer
            )
        )
    )

    add_time(query, 5 + i * 8)
    add_time(response, 5.02 + i * 8)


# ============================================================
# 2. NORMAL INTERNAL HTTP TRAFFIC
# ============================================================

normal_requests = [
    (
        40,
        b"GET /dashboard HTTP/1.1\r\n"
        b"Host: intranet.blackout.local\r\n"
        b"User-Agent: Mozilla/5.0\r\n"
        b"Connection: keep-alive\r\n\r\n"
    ),
    (
        42,
        b"GET /shared/ HTTP/1.1\r\n"
        b"Host: files.blackout.local\r\n"
        b"User-Agent: Mozilla/5.0\r\n"
        b"Connection: keep-alive\r\n\r\n"
    ),
]

for offset, payload in normal_requests:
    add_time(
        tcp_packet(
            CLIENT,
            INTERNAL_WEB,
            49152 + offset,
            80,
            payload
        ),
        offset
    )


# ============================================================
# 3. SUSPICIOUS DNS LOOKUP
# ============================================================

dns_sport = 54000

dns_query = (
    IP(src=CLIENT, dst=DNS_SERVER)
    / UDP(sport=dns_sport, dport=53)
    / DNS(
        id=777,
        qr=0,
        rd=1,
        qd=DNSQR(qname=C2_DOMAIN)
    )
)

dns_response = (
    IP(src=DNS_SERVER, dst=CLIENT)
    / UDP(sport=53, dport=dns_sport)
    / DNS(
        id=777,
        qr=1,
        rd=1,
        ra=1,
        qd=DNSQR(qname=C2_DOMAIN),
        an=DNSRR(
            rrname=C2_DOMAIN,
            type="A",
            ttl=120,
            rdata=C2_IP
        )
    )
)

add_time(dns_query, 68)
add_time(dns_response, 68.02)


# ============================================================
# 4. PERIODIC C2 BEACONING
# ============================================================

beacon_times = [75, 135, 195, 255, 315, 375, 435, 495]

for number, offset in enumerate(beacon_times, start=1):

    sport = 51000 + number

    request = (
        f"POST /api/v1/checkin HTTP/1.1\r\n"
        f"Host: {C2_DOMAIN}\r\n"
        f"User-Agent: BlackoutUpdater/1.4\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Content-Length: 42\r\n"
        f"Connection: keep-alive\r\n\r\n"
        f"HOST=OPS-WS-17;ID={number:04d};STATUS=OK"
    ).encode()

    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: nginx\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: 18\r\n"
        b"Connection: keep-alive\r\n\r\n"
        b"CMD_NONE;SLEEP=60"
    )

    add_time(
        tcp_packet(
            CLIENT,
            C2_IP,
            sport,
            8080,
            request
        ),
        offset
    )

    add_time(
        tcp_packet(
            C2_IP,
            CLIENT,
            8080,
            sport,
            response
        ),
        offset + 0.04
    )


# ============================================================
# 5. C2 TASK / COMMAND
# ============================================================

command_request = (
    f"POST /api/v1/task HTTP/1.1\r\n"
    f"Host: {C2_DOMAIN}\r\n"
    f"User-Agent: BlackoutUpdater/1.4\r\n"
    f"Content-Type: application/octet-stream\r\n"
    f"Content-Length: 25\r\n\r\n"
    f"CMD=COLLECT&PATH=/tmp/log"
).encode()

command_response = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: nginx\r\n"
    b"Content-Length: 22\r\n\r\n"
    b"TASK=COLLECT_LOGS;ID=7"
)

add_time(
    tcp_packet(
        CLIENT,
        C2_IP,
        51100,
        8080,
        command_request
    ),
    525
)

add_time(
    tcp_packet(
        C2_IP,
        CLIENT,
        8080,
        51100,
        command_response
    ),
    525.05
)


# ============================================================
# 6. OUTBOUND DATA TRANSFER
# ============================================================

upload_request = (
    f"POST /api/v1/upload HTTP/1.1\r\n"
    f"Host: {C2_DOMAIN}\r\n"
    f"User-Agent: BlackoutUpdater/1.4\r\n"
    f"Content-Type: application/octet-stream\r\n"
    f"Content-Length: 47\r\n\r\n"
    f"FILE=incident.log;SIZE=2048;HASH=9f2c1a77"
).encode()

upload_response = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: nginx\r\n"
    b"Content-Length: 12\r\n\r\n"
    b"UPLOAD_OK=1"
)

add_time(
    tcp_packet(
        CLIENT,
        C2_IP,
        51200,
        8080,
        upload_request
    ),
    560
)

add_time(
    tcp_packet(
        C2_IP,
        CLIENT,
        8080,
        51200,
        upload_response
    ),
    560.04
)


# ============================================================
# 7. EXTRA BACKGROUND TRAFFIC / NOISE
# ============================================================

background_hosts = [
    "192.168.10.11",
    "192.168.10.12",
    "192.168.10.20",
]

for i, host in enumerate(background_hosts):
    sport = 55000 + i

    syn = IP(src=CLIENT, dst=host) / TCP(
        sport=sport,
        dport=443,
        flags="S"
    )

    synack = IP(src=host, dst=CLIENT) / TCP(
        sport=443,
        dport=sport,
        flags="SA"
    )

    add_time(syn, 90 + i * 17)
    add_time(synack, 90.03 + i * 17)


# ============================================================
# WRITE PCAP
# ============================================================

OUT.parent.mkdir(parents=True, exist_ok=True)

packets.sort(key=lambda p: p.time)

wrpcap(str(OUT), packets)

print("=" * 55)
print("BLACKOUT STAGE 05 PCAP GENERATED")
print("=" * 55)
print(f"Output : {OUT}")
print(f"Packets: {len(packets)}")
print(f"Size   : {OUT.stat().st_size} bytes")
print("=" * 55)
