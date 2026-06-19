# Flag-lab setup & runner provisioning

The flag-lab (`grin lab`) needs two things beyond the repo: a Docker daemon the operator
user can reach, and an offensive **runner** container (`grin-kali`) provisioned with tools +
wordlists. The target containers themselves are fully defined in `lab/` and built by
`grin lab up`; this doc covers the manual rig state the lab depends on.

Validated on the user rig (NixOS, RTX 3060 12 GB, Ollama local). Phase-1 gate is GREEN:
an autonomous `grin engage` against T1 captured the flag end-to-end with the default local
model (`qwen3:14b`) once the deterministic extractor landed.

## Target ladder (increasing difficulty)

| id | ip | tier | vuln / intended chain |
|----|----|------|------------------------|
| t1-ssh   | .11 | easy   | weak SSH creds -> ssh -> flag |
| t2-web   | .12 | medium | web OS command injection -> read /flag.txt |
| t3-chain | .13 | hard   | cmd-injection foothold -> `sudo find` GTFOBins privesc -> root flag |
| t4-crack | .14 | expert | path-traversal file disclosure (**no hint**) -> find user via `/etc/passwd` + hash in `/var/backups` -> **offline crack** (`john` + rockyou) -> SSH -> flag |
| t5-ssti  | .15 | elite  | **Jinja2 SSTI** -> RCE as low-priv -> **PATH-hijack of a SUID helper** (`/usr/local/bin/syscheck`) -> root flag |
| t6-pivot | .16 (+ .17 vault) | master | cmd-injection -> steal a **passphrase-locked** SSH key -> **crack it** (`ssh2john`+rockyou) -> **scan to find** the vault (.17) -> **pivot** -> flag |

These are deliberately un-guided. T4 plants no breadcrumb to the backup — the agent must know to
read `/etc/passwd` for the user and check the classic `/var/backups` location, then crack offline.
T5's privesc is a PATH hijack on a custom SUID binary (no GTFOBins `find` shortcut — that bit isn't
set): enumerate SUID, inspect the helper, hijack PATH. T6 discloses neither the vault's host nor an
unlocked key: the agent must crack the key passphrase offline, discover the vault by scanning the
in-scope subnet, and pivot. Each remains solvable with the tooling on `grin-kali`.

**Model backend:** Grin is cloud-default when configured — set `GRIN_MODEL_BACKEND=openai`,
`GRIN_MODEL_URL`, and `GRIN_MODEL_API_KEY` (e.g. via `~/.grin/deepseek.env`) to use an
OpenAI-compatible cloud endpoint such as DeepSeek. When those vars are absent, Grin falls
back to local Ollama. An explicit `GRIN_MODEL_BACKEND` always wins.

## 1. Docker access for the operator user (NixOS, declarative)

The lab control and the docker runner shell out to Docker, so the operator user needs the
`docker` group. On the user rig this is declarative in `/etc/nixos/configuration.nix`:

```nix
users.users.operator.extraGroups = [ "wheel" "networkmanager" "video" "libvirtd" "docker" ];
```

Then `nixos-rebuild switch` and re-login (or `runuser -l operator`). NOTE: docker-group access is
root-equivalent; acceptable here because the operator already has sudo/wheel.

## 2. The runner container (`grin-kali`)

The Kali base image (`kalilinux/kali-rolling`) ships almost nothing — install the toolset:

```bash
docker exec grin-kali sh -c "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  openssh-client sshpass hydra curl wget netcat-traditional sqlmap nikto nmap iputils-ping wordlists"
docker exec grin-kali sh -c "gunzip -f /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true"
```

### Curated credential lists (fast, solvable T1)

rockyou is 14M lines — brute-forcing it over SSH times out. Ship small curated lists so a
credential attack completes in seconds; the executor prompt points hydra at these:

```bash
docker exec grin-kali sh -c "printf 'root\nadmin\nuser\noperator\nubuntu\npi\nguest\ntest\noracle\npostgres\nmysql\nadministrator\ndeploy\nservice\n' > /usr/share/wordlists/users.txt"
docker exec grin-kali sh -c "printf 'password\n123456\nadmin\nroot\npassword123\nletmein\nqwerty\nchangeme\ntoor\n12345678\nadmin123\nwelcome\nP@ssw0rd\niloveyou\nmonkey\ndragon\n' > /usr/share/wordlists/passwords.txt"
```

### SSH client: don't prompt on unknown host keys

A credential attack must SSH into a freshly-built target whose host key isn't trusted yet.
Without this, `sshpass` aborts with exit code 6 ("host key unknown"):

```bash
docker exec grin-kali sh -c "printf 'Host *\n    StrictHostKeyChecking no\n    UserKnownHostsFile /dev/null\n    LogLevel ERROR\n' >> /etc/ssh/ssh_config"
```

### web-rce helper (deterministic web-RCE payload encoding)

The agent reliably gets SSTI / command-injection RCE but reliably fails to hand-encode a multi-step
payload through a URL param (spaces break it, base64 `+`/`/`/`=` corrupt, pipes/braces need
escaping). `grin/tools/webexec.py` does it correctly; deploy it onto the runner as `web-rce` so the
executor can run any shell command/privesc chain through a web foothold in one shot (this is what
closes T5's SSTI -> SUID PATH-hijack autonomously):

```bash
docker cp grin/tools/webexec.py grin-kali:/usr/local/bin/web-rce
docker exec grin-kali sh -c "chmod +x /usr/local/bin/web-rce"
# usage: web-rce --url http://t/ --param name --mode ssti|cmdi|auto [--method GET|POST] --cmd '<script>'
```

`ssh-loot` does the same for the SSH-pivot last mile — given a stolen (passphrase-protected) key it
cracks + decrypts + tries candidate users (incl. one named in a README) + reads the flag from home,
closing T6's pivot deterministically:

```bash
docker cp grin/tools/sshloot.py grin-kali:/usr/local/bin/ssh-loot
docker exec grin-kali sh -c "chmod +x /usr/local/bin/ssh-loot"
# usage: ssh-loot --host <vault-ip> --key /tmp/loot/id_rsa [--readme '<clue>'] [--passphrase <pw>]
```

`suid-hijack` closes the SUID-privesc last mile — it drives `web-rce` to enumerate SUID binaries,
find the one that calls a program by bare name, and PATH-hijack it (works even when the target lacks
`strings`, by trying candidate commands):

```bash
docker cp grin/tools/suidhijack.py grin-kali:/usr/local/bin/suid-hijack
docker exec grin-kali sh -c "chmod +x /usr/local/bin/suid-hijack"
# usage: suid-hijack --url http://t/ --param name --mode ssti|cmdi|auto --flag /root/flag.txt
```

`web-scan` is the FIND side of the web surface — before you can `web-rce` a foothold you have to
discover the injectable parameter. `grin/tools/webscan.py` fetches the page, extracts every form
input + query param, also probes a candidate list of commonly-unlinked params, sprays each with
XSS payloads, and reports the exact `param=<p> payload=<...>` that reflects UNescaped (a real,
reproducible reflected-XSS injection point — the web coverage CLI scanners miss or bury in noise):

```bash
docker cp grin/tools/webscan.py grin-kali:/usr/local/bin/web-scan
docker exec grin-kali sh -c "chmod +x /usr/local/bin/web-scan"
# usage: web-scan --url http://t/ [--param <p>] [--method GET|POST]
```

`grin-shell` drives INTERACTIVE tools the one-shot executor can't (msfconsole / meterpreter /
interactive sqlmap / evil-winrm / ssh / ftp): it spawns the tool, feeds each `--step` at its prompt,
auto-answers routine confirmations, and returns the transcript. Needs `python3-pexpect` on the runner
(the provisioner installs it). Fail-closed: password/sudo prompts are answered only from `--secret`,
never fabricated.

```bash
docker cp grin/tools/idrive.py grin-kali:/usr/local/bin/grin-shell
docker exec grin-kali sh -c "chmod +x /usr/local/bin/grin-shell"
# usage: grin-shell --cmd 'msfconsole -q' --step 'use ...' --step 'run' --step 'exit'
#        grin-shell --cmd 'ssh user@t' --step 'id' --step 'cat ~/flag.txt' [--secret password=<pw>]
```

## 3. Bring the lab up

```bash
cd ~/grin
python3 -m grin.cli lab up        # build + start all targets (7 containers) on the internal grin-lab net
python3 -m grin.cli lab status    # confirm running + runner-reach=open for each
python3 -m grin.cli lab engagements examples/lab   # generate engagement YAMLs
```

The host-networked `grin-kali` reaches the `internal: true` lab targets (172.30.0.11-17) via
the host bridge route — no `docker network connect` needed.

## 4. Run an engagement (needs the docker python SDK + pyyaml + httpx)

```bash
nix-shell -p 'python3.withPackages(ps: with ps; [ pyyaml httpx docker ])' --run \
  "python3 -m grin.cli engage examples/lab/lab-t1-ssh.yaml --goal 'capture the flag in the home directory'"
python3 -m grin.cli loot examples/lab/lab-t1-ssh.yaml
```

The `docker` python package is REQUIRED for the docker runner; without it the engine silently
falls back to FakeRunner (no real execution).

## Per-engagement hygiene

`grin lab reset` restarts the targets (pristine state). The audit/loot/results/journals dirs are
append-only per engagement id — clear them (`rm -rf audit loot results journals`) before a clean
run or a benchmark, or runs accumulate. (Phase 2 `labbench` will handle this automatically.)

## Reproducible provisioning

`lab/provision-runner.sh` bakes everything in §2 into the runner in one idempotent step — toolset
(incl. `john`), rockyou, curated credential lists, ssh_config, AND the deterministic helpers
(`web-rce` / `ssh-loot` / `suid-hijack`). Run from the repo root after `grin lab up`:

```bash
bash lab/provision-runner.sh            # default container: grin-kali
bash lab/provision-runner.sh <name>     # custom runner
```

This is what makes the consistent 6/6 result (see `MORNING-REPORT-2026-06-18.md`) reproducible from a
clean rig. (A `grin lab provision` subcommand wrapping this remains a nice-to-have.)
