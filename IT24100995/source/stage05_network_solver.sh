#!/bin/bash
set -u

DOMAIN="cdn-sync.blackout-update.net"
C2_IP="10.20.30.50"
CLIENT_IP="192.168.10.25"
C2_PORT="8080"
FLAG="FLAG{blackout_c2}"

PCAP="static/evidence/stage05/network_capture.pcap"

if [ ! -f "$PCAP" ]; then
    PCAP="$HOME/Downloads/network_capture.pcap"
fi

if [ ! -f "$PCAP" ]; then
    echo "[ERROR] PCAP file not found."
    exit 1
fi

if ! command -v tshark >/dev/null 2>&1; then
    echo "[ERROR] tshark is not installed."
    exit 1
fi

echo "=========================================="
echo " BLACKOUT - STAGE 05 NETWORK INVESTIGATION"
echo "=========================================="
echo "Evidence: $PCAP"

echo
echo "[1] DNS IOC Analysis"

DNS=$(tshark -r "$PCAP" \
    -Y "dns.qry.name == \"$DOMAIN\"" \
    -T fields -e dns.qry.name -e dns.a 2>/dev/null)

if echo "$DNS" | grep -Fq "$DOMAIN" &&
   echo "$DNS" | grep -Fq "$C2_IP"; then
    echo "[+] Domain: $DOMAIN"
    echo "[+] Resolved IP: $C2_IP"
    DNS_OK=1
else
    echo "[-] DNS correlation failed."
    DNS_OK=0
fi

echo
echo "[2] Check-in Activity"

CHECKINS=$(tshark -r "$PCAP" \
    -d tcp.port==8080,http \
    -Y "ip.src == $CLIENT_IP && ip.dst == $C2_IP && tcp.dstport == $C2_PORT && http.request.uri == \"/api/v1/checkin\"" \
    -T fields -e frame.time_relative 2>/dev/null)

COUNT=$(printf '%s\n' "$CHECKINS" | grep -c '[0-9]' || true)

if [ "$COUNT" -ge 2 ]; then
    echo "[+] Repeated check-ins confirmed."
    echo "[+] Requests found: $COUNT"
    echo "$CHECKINS"
    BEACON_OK=1
else
    echo "[!] HTTP filter did not count all check-ins."
    echo "[!] Checking the known TCP stream payload..."

    STREAM=$(tshark -r "$PCAP" \
        -q -z follow,tcp,ascii,2 2>/dev/null || true)

    if echo "$STREAM" | grep -Fq '/api/v1/checkin' &&
       echo "$STREAM" | grep -Fq 'SLEEP=60'; then
        echo "[+] Check-in request and 60-second sleep evidence found."
        BEACON_OK=1
    else
        echo "[-] Check-in evidence not confirmed."
        BEACON_OK=0
    fi
fi

echo
echo "[3] Task Retrieval"

TASK=$(tshark -r "$PCAP" \
    -q -z follow,tcp,ascii,13 2>/dev/null || true)

if echo "$TASK" | grep -Fq 'CMD=COLLECT&PATH=/tmp/log'; then
    echo "[+] Task request confirmed."
    echo "[+] CMD=COLLECT&PATH=/tmp/log"
    TASK_OK=1
else
    echo "[-] Task retrieval not confirmed."
    TASK_OK=0
fi

echo
echo "[4] File Upload"

UPLOAD=$(tshark -r "$PCAP" \
    -q -z follow,tcp,ascii,14 2>/dev/null || true)

if echo "$UPLOAD" | grep -Fq 'FILE=incident.log' &&
   echo "$UPLOAD" | grep -Fq 'UPLOAD_OK=1'; then
    echo "[+] File upload confirmed."
    echo "[+] FILE=incident.log"
    UPLOAD_OK=1
else
    echo "[-] File upload not confirmed."
    UPLOAD_OK=0
fi

echo
echo "[5] Evidence Correlation"

if [ "$DNS_OK" -eq 1 ] &&
   [ "$BEACON_OK" -eq 1 ] &&
   [ "$TASK_OK" -eq 1 ] &&
   [ "$UPLOAD_OK" -eq 1 ]; then

    echo "[+] DNS IOC confirmed."
    echo "[+] Periodic check-in behaviour confirmed."
    echo "[+] Task retrieval confirmed."
    echo "[+] File upload confirmed."

    echo
    echo "Investigation conclusion: Command-and-Control (C2)"
    echo "Recovered flag: $FLAG"
else
    echo "[-] Evidence checks incomplete."
    echo "[-] No flag generated; investigate the failed check."
    exit 1
fi

echo "=========================================="
