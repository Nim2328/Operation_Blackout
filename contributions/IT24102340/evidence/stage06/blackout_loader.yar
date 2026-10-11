rule BLACKOUT_Suspicious_Loader
{
    meta:
        description = "Detects BLACKOUT loader indicators and its memory-resident encoded artifact"
        author = "Operation Blackout"
        case_reference = "BLACKOUT-MEM-06"

    strings:
        $host = "OPS-WS-17"
        $task = "C2_TASK=COLLECT"
        $target = "/var/log/auth.log"
        $server = "cdn-sync.blackout-update.net"
        $ua = "BlackoutUpdater/1.4"
        $port = "PORT=8080"
        $interval = "INTERVAL=45"

        $artifact_marker = "BLACKOUT_MEMORY_ARTIFACT"
        $encoded_flag = "RkxBR3ttYWx3YXJlX2xvYWRlcn0="

    condition:
        5 of ($host, $task, $target, $server, $ua, $port, $interval)
        and $artifact_marker
        and $encoded_flag
}
