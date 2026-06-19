#!/usr/bin/env bash
# T1 exploit-model mini-benchmark. Run inside the nix-shell (python3 + pyyaml httpx docker).
set -u
cd ~/grin || exit 1
EXP=$(grep -m1 'flag:' lab/answers.yaml | awk '{print $2}' | tr -d '"')
echo "expected flag: $EXP"
MODELS=(qwen3:14b whiterabbitneo:13b dolphin3:8b hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M)
for M in "${MODELS[@]}"; do
  for i in 1 2; do
    rm -rf audit loot results journals
    python3 -m grin.cli lab reset >/dev/null 2>&1
    python3 -m grin.cli engage examples/lab/lab-t1-ssh.yaml \
      --goal 'capture the flag in the home directory' --exploit-model "$M" >/tmp/g.log 2>&1
    FLAG=no; grep -rq "$EXP" loot audit 2>/dev/null && FLAG=YES
    CRED=no; grep -rq 'admin:password' loot 2>/dev/null && CRED=YES
    NLOOT=$(find . -name secrets.jsonl -exec cat {} + 2>/dev/null | wc -l)
    echo "RESULT $M run$i: flag=$FLAG real_cred=$CRED loot_lines=$NLOOT"
  done
done
echo "BENCH DONE"
