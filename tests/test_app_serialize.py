from dataclasses import dataclass
import json
from grin.app.serialize import to_jsonable

@dataclass
class P:
    a: int
    b: str

def test_dataclass_becomes_dict():
    assert to_jsonable(P(1, "x")) == {"a": 1, "b": "x"}

def test_nested_list_of_dataclasses():
    out = to_jsonable([P(1, "x"), {"k": P(2, "y")}])
    assert out == [{"a": 1, "b": "x"}, {"k": {"a": 2, "b": "y"}}]
    json.dumps(out)  # must be JSON-serializable

def test_primitives_passthrough():
    assert to_jsonable("s") == "s"
    assert to_jsonable(3) == 3
    assert to_jsonable(None) is None
