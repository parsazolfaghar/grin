from grin.brain import Brain, detect_situations


def test_record_and_retrieve_playbook(tmp_path):
    b = Brain(path=str(tmp_path / "lessons.jsonl"))
    b.record("root-owned-flag", "use sudo-gtfo to escalate", kind="playbook", outcome="worked")
    out = b.lessons_for(["root-owned-flag"])
    assert len(out) == 1
    assert out[0].text == "use sudo-gtfo to escalate"
    assert out[0].worked == 1 and out[0].failed == 0


def test_record_reinforces_existing(tmp_path):
    b = Brain(path=str(tmp_path / "l.jsonl"))
    b.record("stolen-ssh-key", "use ssh-loot", kind="playbook", outcome="worked")
    b.record("stolen-ssh-key", "use ssh-loot", kind="playbook", outcome="worked")
    b.record("stolen-ssh-key", "use ssh-loot", kind="playbook", outcome="failed")
    out = b.lessons_for(["stolen-ssh-key"])
    assert len(out) == 1                       # deduped, not three rows
    assert out[0].worked == 2 and out[0].failed == 1


def test_persists_across_instances(tmp_path):
    p = str(tmp_path / "l.jsonl")
    Brain(path=p).record("ssti", "use suid-hijack", kind="playbook", outcome="worked")
    out = Brain(path=p).lessons_for(["ssti"])
    assert out and out[0].text == "use suid-hijack"


def test_lessons_for_only_matching_situations(tmp_path):
    b = Brain(path=str(tmp_path / "l.jsonl"))
    b.record("root-owned-flag", "sudo-gtfo", kind="playbook", outcome="worked")
    b.record("stolen-ssh-key", "ssh-loot", kind="playbook", outcome="worked")
    out = b.lessons_for(["stolen-ssh-key"])
    assert [x.text for x in out] == ["ssh-loot"]


def test_playbooks_rank_before_pitfalls_and_by_score(tmp_path):
    b = Brain(path=str(tmp_path / "l.jsonl"))
    b.record("s", "weak play", kind="playbook", outcome="worked")
    b.record("s", "strong play", kind="playbook", outcome="worked")
    b.record("s", "strong play", kind="playbook", outcome="worked")
    b.record("s", "a pitfall", kind="pitfall", outcome="failed")
    out = b.lessons_for(["s"])
    assert out[0].text == "strong play"          # higher net score first
    assert out[1].text == "weak play"
    assert out[-1].kind == "pitfall"             # pitfalls last


def test_render_block_groups_play_and_avoid(tmp_path):
    b = Brain(path=str(tmp_path / "l.jsonl"))
    b.record("root-owned-flag", "use sudo-gtfo", kind="playbook", outcome="worked")
    b.record("flag-not-captured", "do not declare done without GRIN{ flag", kind="pitfall",
             outcome="failed")
    txt = b.render(["root-owned-flag", "flag-not-captured"])
    assert "use sudo-gtfo" in txt
    assert "do not declare done" in txt.lower()
    assert txt.strip() != ""


def test_render_empty_when_no_match(tmp_path):
    b = Brain(path=str(tmp_path / "l.jsonl"))
    b.record("x", "y", kind="playbook", outcome="worked")
    assert b.render(["unrelated"]) == ""


# ---- situation detection from a run's history text ----

def test_detect_root_owned_flag():
    hist = "cat /root/flag.txt\ncat: /root/flag.txt: Permission denied"
    assert "root-owned-flag" in detect_situations(hist, target="172.30.0.13")


def test_detect_stolen_ssh_key():
    hist = "cat /opt/deploy/id_rsa\n-----BEGIN OPENSSH PRIVATE KEY-----"
    assert "stolen-ssh-key" in detect_situations(hist, target="172.30.0.16")


def test_detect_ssti_foothold():
    hist = "curl 'http://t/?name={{7*7}}' -> Hello, 49"
    assert "ssti-foothold" in detect_situations(hist, target="t")


def test_unproven_fires_only_with_foothold_and_no_proof():
    # no foothold yet -> don't nag
    assert "flag-not-captured" not in detect_situations("nmap scan done", target="t")
    # foothold (cmdi) but no proof -> nag to keep going
    assert "flag-not-captured" in detect_situations(
        "web-rce ... uid=33(www-data)", target="t")
    # proof present -> no nag
    assert "flag-not-captured" not in detect_situations(
        "web-rce ... uid=33(www-data) got GRIN{abc123}", target="t")


def test_ensure_seeded_populates_then_is_idempotent(tmp_path):
    b = Brain(path=str(tmp_path / "l.jsonl"))
    b.ensure_seeded()
    n = len(b.lessons_for(["root-owned-flag"]) + b.lessons_for(["stolen-ssh-key"]))
    assert n >= 2
    b.ensure_seeded()  # idempotent — no duplicates
    again = Brain(path=str(tmp_path / "l.jsonl"))
    assert len(again.lessons_for(["root-owned-flag"])) == 1


def test_sync_seeds_adds_new_without_wiping_learning(tmp_path):
    from grin.brain import DEFAULT_SEEDS
    p = str(tmp_path / "l.jsonl")
    b = Brain(path=p)
    b.ensure_seeded()
    # simulate a learned reinforcement on an existing seed
    s0_sit, _s0_kind, s0_text = DEFAULT_SEEDS[0]
    b.record(s0_sit, s0_text, kind="playbook", outcome="worked")
    learned = next(x for x in b.lessons_for([s0_sit]) if x.text == s0_text).worked
    # a new release adds a brand-new lesson the user's brain hasn't seen
    b.record("new-situation-xyz", "obsolete user lesson", kind="pitfall", outcome="failed")
    before = len(b._lessons)
    added = Brain(path=p).sync_seeds()        # update path on a fresh instance
    assert added == 0                          # all current seeds already present -> nothing new
    # the learned reinforcement is untouched
    b2 = Brain(path=p)
    assert next(x for x in b2.lessons_for([s0_sit]) if x.text == s0_text).worked == learned
    # the user's own learned lesson survives the sync
    assert any(x.text == "obsolete user lesson" for x in b2.lessons_for(["new-situation-xyz"]))
    assert len(b2._lessons) == before


def test_sync_seeds_on_empty_adds_all(tmp_path):
    from grin.brain import DEFAULT_SEEDS
    b = Brain(path=str(tmp_path / "l.jsonl"))
    added = b.sync_seeds()
    assert added == len(DEFAULT_SEEDS)


def test_seeded_brain_renders_helper_for_situation(tmp_path):
    b = Brain(path=str(tmp_path / "l.jsonl"))
    b.ensure_seeded()
    txt = b.render(["root-owned-flag"])
    assert "sudo-gtfo" in txt


def test_build_step_prompt_injects_brain_lessons(tmp_path):
    from grin.journal import Journal
    from grin.prompts import build_step_prompt
    b = Brain(path=str(tmp_path / "l.jsonl"))
    b.ensure_seeded()
    j = Journal(task_id="x", objective="o", target="172.30.0.13", engagement_path="e", path=str(tmp_path / "j.json"))
    # a history that signals a root-owned flag should pull the sudo-gtfo play into the prompt
    from grin.journal import Step
    j.add_step(Step(action={"command": "cat /root/flag.txt"}, decision="executed",
                    output="cat: /root/flag.txt: Permission denied", exit_code=1))
    _system, user = build_step_prompt("o", "172.30.0.13", j, ["exploit"], brain=b)
    assert "sudo-gtfo" in user
    assert "LEARNED" in user


def test_build_step_prompt_without_brain_is_unchanged(tmp_path):
    from grin.journal import Journal
    from grin.prompts import build_step_prompt
    j = Journal(task_id="x", objective="o", target="t", engagement_path="e", path=str(tmp_path / "j.json"))
    _system, user = build_step_prompt("o", "t", j, ["exploit"])
    assert "LEARNED" not in user
