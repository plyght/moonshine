#!/bin/sh
# netsim.sh — simulate a faraway/lossy link for a udp port (macOS dummynet+pf).
# usage:
#   sudo scripts/netsim.sh on  [port] [rtt_ms] [loss_pct]   (defaults 4433 150 0)
#   sudo scripts/netsim.sh off
set -e
cmd="$1"; port="${2:-4433}"; rtt="${3:-150}"; loss="${4:-0}"
half=$((rtt / 2))
plr=$(awk "BEGIN{printf \"%.4f\", $loss/100}")

case "$cmd" in
  on)
    dnctl pipe 1 config delay "${half}ms" plr "$plr"
    printf '%s\n' \
      "dummynet in  quick proto udp from any to any port $port pipe 1" \
      "dummynet in  quick proto udp from any port $port to any pipe 1" \
      "dummynet out quick proto udp from any to any port $port pipe 1" \
      "dummynet out quick proto udp from any port $port to any pipe 1" \
      | pfctl -f - -e
    echo "netsim ON: ~${rtt}ms RTT, ${loss}% loss on udp/${port}"
    ;;
  off)
    pfctl -d 2>/dev/null || true
    dnctl -q flush 2>/dev/null || true
    echo "netsim OFF"
    ;;
  *)
    echo "usage: sudo scripts/netsim.sh on [port] [rtt_ms] [loss_pct] | off" >&2
    exit 1
    ;;
esac
