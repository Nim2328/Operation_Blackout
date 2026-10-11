import os
import subprocess
import textwrap

workdir = "static/evidence/stage06"
os.makedirs(workdir, exist_ok=True)

source = r'''
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

char command_buffer[256] =
    "C2_TASK=COLLECT|TARGET=/var/log/auth.log|INTERVAL=45";

char config_blob[512] =
    "UPDATE_CHANNEL=stable;"
    "SERVER=cdn-sync.blackout-update.net;"
    "PORT=8080;"
    "USER_AGENT=BlackoutUpdater/1.4;";

char encoded_blob[] =
    "Q09MTEVDVF9BVVRIX0xPR19EQVRB";

void suspicious_worker(void) {
    char memory_data[1024];

    snprintf(
        memory_data,
        sizeof(memory_data),
        "OPS-WS-17|TASK=%s|CONFIG=%s",
        command_buffer,
        config_blob
    );

    while (1) {
        sleep(10);
    }
}

int main(void) {
    printf("Blackout updater service started. PID=%d\n", getpid());
    fflush(stdout);

    suspicious_worker();

    return 0;
}
'''

src = "/tmp/blackout_loader.c"
binary = "/tmp/blackout_loader"

with open(src, "w") as f:
    f.write(source)

subprocess.run(
    ["gcc", "-g", "-O0", "-o", binary, src],
    check=True
)

print("[+] Compiled:", binary)

print("[+] Starting simulated malicious loader...")

proc = subprocess.Popen(
    [binary],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

print(proc.stdout.readline().strip())
print("[+] PID:", proc.pid)

print("[+] Generating core dump...")

core = os.path.join(workdir, "ops_ws17_loader.core")

subprocess.run(
    ["gcore", "-o", core.replace(".core", ""), str(proc.pid)],
    check=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

generated = core

if not os.path.exists(generated):
    generated = core.replace(".core", "") + "." + str(proc.pid)

os.rename(generated, core)

proc.terminate()

print("[+] Core dump created:", core)

print("[+] Size:", os.path.getsize(core), "bytes")

print()
print("=" * 55)
print("STAGE 06 MEMORY ARTIFACT GENERATED")
print("=" * 55)
print("Artifact :", core)
print("PID      :", proc.pid)
print("Format   : ELF core dump")
print("=" * 55)
