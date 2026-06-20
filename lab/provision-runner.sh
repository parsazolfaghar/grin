#!/usr/bin/env bash
# Provision the Grin lab runner (grin-kali) reproducibly: offensive toolset + wordlists + ssh_config
# + the deterministic exploit helpers (web-rce / ssh-loot / suid-hijack). Idempotent — safe to re-run.
# Run from the repo root:  bash lab/provision-runner.sh [container]   (default container: grin-kali)
set -eu
C="${1:-grin-kali}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "[*] toolset"
# NOTE: hydra/medusa are deliberately NOT installed here — they live ONLY on the BlackArch arsenal,
# so brute-force steps route there (verifies grin uses both arsenals). Keep this list helper-friendly.
docker exec "$C" sh -c "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  openssh-client sshpass curl wget netcat-traditional sqlmap nikto nmap iputils-ping \
  wordlists john python3 python3-pexpect >/dev/null 2>&1 || true; \
  apt-get remove -y -qq hydra medusa >/dev/null 2>&1 || true"

echo "[*] rockyou"
docker exec "$C" sh -c "gunzip -f /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true"

echo "[*] curated credential lists (into the runner AND the brute arsenal that owns hydra)"
# hydra/medusa live on grin-blackarch (arsenal split), so the curated wordlists MUST exist there too
# — otherwise an SSH/web brute routed to BlackArch has no list. Seed both, best-effort.
_USERS='root\nadmin\nuser\noperator\nubuntu\npi\nguest\ntest\noracle\npostgres\nmysql\nadministrator\ndeploy\nservice\n'
_PASS='password\n123456\nadmin\nroot\npassword123\nletmein\nqwerty\nchangeme\ntoor\n12345678\nadmin123\nwelcome\nP@ssw0rd\niloveyou\nmonkey\ndragon\n'
for WC in "$C" grin-blackarch; do
  docker exec "$WC" sh -c "mkdir -p /usr/share/wordlists; printf '$_USERS' > /usr/share/wordlists/users.txt; printf '$_PASS' > /usr/share/wordlists/passwords.txt" 2>/dev/null || true
done

echo "[*] ssh client (don't prompt on unknown host keys)"
docker exec "$C" sh -c "grep -q 'StrictHostKeyChecking no' /etc/ssh/ssh_config 2>/dev/null || \
  printf 'Host *\n    StrictHostKeyChecking no\n    UserKnownHostsFile /dev/null\n    LogLevel ERROR\n' >> /etc/ssh/ssh_config"

echo "[*] deterministic exploit helpers"
for h in webexec:web-rce sshloot:ssh-loot suidhijack:suid-hijack webscan:web-scan idrive:grin-shell sudoesc:sudo-gtfo; do
  src="${h%%:*}"; dst="${h##*:}"
  docker cp "$ROOT/grin/tools/$src.py" "$C:/usr/local/bin/$dst" >/dev/null
  docker exec "$C" sh -c "sed -i '1s|.*|#!/usr/bin/env python3|' /usr/local/bin/$dst && chmod +x /usr/local/bin/$dst"
done

echo "[*] verify"
docker exec "$C" sh -c "command -v nmap hydra john ssh-loot web-rce suid-hijack web-scan grin-shell sudo-gtfo >/dev/null && echo '    OK: tools + helpers present' || echo '    WARN: something missing'"
echo "[done] runner '$C' provisioned"
