"""A captured Secret — credentials/keys/tokens/hashes obtained during an engagement. Stored in
full (no redaction) as proof of exposure. Provenance (objective + timestamp) is added by the
loot store when written; the model supplies the rest."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Secret:
    label: str
    value: str
    target: str
    tool: str
    command: str
    context: str = ""
