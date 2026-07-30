#!/usr/bin/env bash
#
# Install the NexusTrace retention timer. Run on the host that serves the app, as root.
#
#   sudo deploy/systemd/install.sh [unix-user]
#
# The unit is templated on the user so it does not hardcode one: the sweep runs as the
# account that owns /opt/NexusTrace, because it deletes files there. Defaults to the
# owner of the checkout.
#
# Report-only is NOT the default: the shipped unit passes --yes and will delete. Run the
# dry-run command this script prints at the end before trusting it.

set -euo pipefail

REPO_DIR="${REPO_DIR:-/opt/NexusTrace}"
UNIT_DIR=/etc/systemd/system
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root (sudo)." >&2; exit 1; }
[ -d "$REPO_DIR/.git" ] || { echo "ERROR: $REPO_DIR is not a checkout. Set REPO_DIR." >&2; exit 1; }
[ -f "$REPO_DIR/scripts/purge_data.py" ] || { echo "ERROR: purge_data.py missing." >&2; exit 1; }

RUN_AS="${1:-$(stat -c '%U' "$REPO_DIR")}"
id "$RUN_AS" >/dev/null 2>&1 || { echo "ERROR: no such user: $RUN_AS" >&2; exit 1; }
command -v uv >/dev/null 2>&1 || echo "WARNING: uv not on root's PATH; check ExecStart resolves for $RUN_AS." >&2

echo "Installing retention timer: repo=$REPO_DIR user=$RUN_AS"

# %i is the instance name, so one unit file serves any user. Installed as a template.
sed "s|/opt/NexusTrace|$REPO_DIR|g" "$SRC/nexustrace-purge.service" \
    > "$UNIT_DIR/nexustrace-purge@.service"
sed "s|/opt/NexusTrace|$REPO_DIR|g" "$SRC/nexustrace-purge.timer" \
    > "$UNIT_DIR/nexustrace-purge@.timer"

mkdir -p "$REPO_DIR/logs"
chown "$RUN_AS" "$REPO_DIR/logs"

systemctl daemon-reload
systemctl enable --now "nexustrace-purge@${RUN_AS}.timer"

echo
echo "Installed. Verify with:"
echo "  systemctl list-timers 'nexustrace-purge@*'"
echo "  journalctl -u nexustrace-purge@${RUN_AS}.service -n 50"
echo
echo "Before trusting it, run the sweep by hand and read what it would remove:"
echo "  sudo -u $RUN_AS sh -c 'cd $REPO_DIR && uv run python scripts/purge_data.py'"
echo
echo "To trigger the real sweep once, now:"
echo "  systemctl start nexustrace-purge@${RUN_AS}.service"
echo
echo "To remove:"
echo "  systemctl disable --now nexustrace-purge@${RUN_AS}.timer"
echo "  rm $UNIT_DIR/nexustrace-purge@.{service,timer} && systemctl daemon-reload"
