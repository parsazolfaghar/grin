"""The ATT&CK-tagged executable technique catalog: tactic -> ATT&CK technique -> Kali/BlackArch
tool templates. Drives the aggressive sweep AND ATT&CK report tagging. Pure. Contains ONLY
access/exploitation techniques — no impact/DoS/destructive entries, by design."""
from dataclasses import dataclass
from pathlib import Path

import yaml

from grin.classes import ACTION_CLASSES


class CatalogError(Exception):
    pass


@dataclass(frozen=True)
class Technique:
    id: str
    tactic: str
    name: str
    action_class: str
    tools: list
    command_templates: list
    applies_when: str


_REQUIRED = ("id", "tactic", "name", "action_class", "tools", "command_templates", "applies_when")


def load_catalog(path: str) -> list:
    try:
        data = yaml.safe_load(Path(path).read_text()) or {}
    except (OSError, yaml.YAMLError) as e:
        raise CatalogError(f"cannot read catalog {path}: {e}") from e
    rows = data.get("techniques") or []
    if not rows:
        raise CatalogError(f"catalog {path} has no techniques")
    out = []
    for i, row in enumerate(rows):
        missing = [k for k in _REQUIRED if k not in row]
        if missing:
            raise CatalogError(f"technique #{i} missing fields: {missing}")
        if row["action_class"] not in ACTION_CLASSES:
            raise CatalogError(
                f"technique {row['id']} bad action_class {row['action_class']!r}; "
                f"expected one of {ACTION_CLASSES}")
        out.append(Technique(
            id=str(row["id"]), tactic=str(row["tactic"]), name=str(row["name"]),
            action_class=str(row["action_class"]), tools=list(row["tools"]),
            command_templates=list(row["command_templates"]), applies_when=str(row["applies_when"])))
    return out


def applies(technique, services) -> bool:
    """services: list of grin.services.Service. Match the technique's applies_when rule."""
    rule = technique.applies_when.strip()
    if rule == "always":
        return True
    if rule.startswith("port:"):
        try:
            want = int(rule.split(":", 1)[1])
        except ValueError:
            return False
        return any(s.port == want for s in services)
    if rule.startswith("service:"):
        want = rule.split(":", 1)[1].strip().lower()
        return any(s.name.lower() == want for s in services)
    return False


def techniques_for(catalog, services) -> list:
    return [t for t in catalog if applies(t, services)]


def tool_to_techniques(catalog) -> dict:
    m = {}
    for t in catalog:
        for tool in t.tools:
            m.setdefault(tool, [])
            if t.id not in m[tool]:
                m[tool].append(t.id)
    return m
