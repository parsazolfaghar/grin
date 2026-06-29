"""assessbench — score grin's assessment findings against known-vulnerable real apps.

Sibling of labbench (which scores CTF flag capture). assessbench measures whether the
assessment pipeline finds REAL vulnerabilities, with precision/recall against a ground-truth
answer key. Built bench-first: the scorer is verifiable with synthetic findings, before the
assessment mode that produces real ones exists. Part of the grin real-target overhaul."""
