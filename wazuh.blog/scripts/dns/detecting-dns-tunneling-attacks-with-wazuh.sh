<!-- Source: https://wazuh.com/blog/detecting-dns-tunneling-attacks-with-wazuh/ | Article: Detecting DNS tunneling attacks with Wazuh -->
#!/usr/bin/env bash
set -euo pipefail

INTERFACE="<YOUR_INTERFACE>"
LOG_FILE="/var/log/dns_monitoring.log"
PID_FILE="/run/dns-monitor.pid"

[[ $EUID -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$PID_FILE")"

start() {
    [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null && { echo "Already running"; exit 0; }
    tcpdump -i "$INTERFACE" -l -nn -vvv port 53 >> "$LOG_FILE" 2>&1 &
    sleep 1
    kill -0 $! 2>/dev/null && echo $! > "$PID_FILE" && echo "Started (PID: $!)" || { echo "Failed to start" >&2; exit 1; }
}

stop() {
    [[ -f "$PID_FILE" ]] || { echo "Not running"; exit 0; }
    PID=$(cat "$PID_FILE")
    kill "$PID" 2>/dev/null && sleep 1 && rm -f "$PID_FILE" && echo "Stopped" || echo "Already stopped"
}

status() {
    [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null && { echo "running (PID: $(cat "$PID_FILE"))"; exit 0; }
    echo "stopped"; exit 1
}

case "${1:-}" in
    start|stop|status) "$1" ;;
    restart) stop; start ;;
    *) echo "Usage: $0 {start|stop|restart|status}" >&2; exit 1 ;;
esac