#!/usr/bin/env bash
# Provision the Grin lab runner (grin-kali) reproducibly: offensive toolset + wordlists + ssh_config
# + the deterministic exploit helpers (web-rce / ssh-loot / suid-hijack). Idempotent — safe to re-run.
# Run from the repo root:  bash lab/provision-runner.sh [container]   (default container: grin-kali)
set -eu
C="${1:-grin-kali}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "[*] toolset"
docker exec "$C" sh -c "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  openssh-client sshpass hydra curl wget netcat-traditional sqlmap nikto nmap iputils-ping \
  wordlists john python3 >/dev/null 2>&1 || true"

echo "[*] rockyou"
docker exec "$C" sh -c "gunzip -f /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true"

echo "[*] curated credential lists"
docker exec "$C" sh -c "printf 'root\nadmin\nuser\noperator\nubuntu\npi\nguest\ntest\noracle\npostgres\nmysql\nadministrator\ndeploy\nservice\n' > /usr/share/wordlists/users.txt"
docker exec "$C" sh -c "printf 'password\n123456\nadmin\nroot\npassword123\nletmein\nqwerty\nchangeme\ntoor\n12345678\nadmin123\nwelcome\nP@ssw0rd\niloveyou\nmonkey\ndragon\n' > /usr/share/wordlists/passwords.txt"

echo "[*] ssh client (don't prompt on unknown host keys)"
docker exec "$C" sh -c "grep -q 'StrictHostKeyChecking no' /etc/ssh/ssh_config 2>/dev/null || \
  printf 'Host *\n    StrictHostKeyChecking no\n    UserKnownHostsFile /dev/null\n    LogLevel ERROR\n' >> /etc/ssh/ssh_config"

echo "[*] deterministic exploit helpers"
for h in webexec:web-rce sshloot:ssh-loot suidhijack:suid-hijack webscan:web-scan; do
  src="${h%%:*}"; dst="${h##*:}"
  docker cp "$ROOT/grin/tools/$src.py" "$C:/usr/local/bin/$dst" >/dev/null
  docker exec "$C" sh -c "sed -i '1s|.*|#!/usr/bin/env python3|' /usr/local/bin/$dst && chmod +x /usr/local/bin/$dst"
done

echo "[*] verify"
docker exec "$C" sh -c "command -v nmap hydra john ssh-loot web-rce suid-hijack web-scan >/dev/null && echo '    OK: tools + helpers present' || echo '    WARN: something missing'"
echo "[done] runner '$C' provisioned"
