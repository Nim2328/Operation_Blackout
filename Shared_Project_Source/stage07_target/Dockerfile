FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y systemd systemd-sysv procps sudo bash && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash analyst

RUN mkdir -p /opt/blackout && \
    chown analyst:analyst /opt/blackout && \
    chmod 775 /opt/blackout

COPY blackout-sync /opt/blackout/blackout-sync
COPY blackout-sync.service /etc/systemd/system/blackout-sync.service

RUN chown analyst:analyst /opt/blackout/blackout-sync && \
    chmod 775 /opt/blackout/blackout-sync

RUN mkdir -p /root && \
    printf '%s\n' 'FLAG{blackout_priv_07}' > /root/stage07_flag.txt && \
    chown root:root /root/stage07_flag.txt && \
    chmod 600 /root/stage07_flag.txt

RUN systemctl enable blackout-sync.service

STOPSIGNAL SIGRTMIN+3

CMD ["/lib/systemd/systemd"]
