from grin.cli import build_parser, DEFAULT_PINS, _resolve_pins


def test_engage_defaults_to_recommended_pins(monkeypatch):
    # argparse now stores None for unspecified role flags; _resolve_pins resolves to the
    # backend's defaults at call time (None means "use backend default").
    monkeypatch.delenv("GRIN_MODEL_BACKEND", raising=False)
    args = build_parser().parse_args(["engage", "e.yaml", "--goal", "x"])
    assert args.planner_model is None
    assert args.recon_model is None
    assert args.exploit_model is None
    # Under the default (ollama) backend, resolution equals the local DEFAULT_PINS.
    pins = _resolve_pins(planner=args.planner_model, recon=args.recon_model,
                         exploit=args.exploit_model)
    assert pins["planner"] == DEFAULT_PINS["planner"]
    assert pins["recon"] == DEFAULT_PINS["recon"]
    assert pins["exploit"] == DEFAULT_PINS["exploit"]


def test_pins_are_overridable(monkeypatch):
    monkeypatch.delenv("GRIN_MODEL_BACKEND", raising=False)
    args = build_parser().parse_args(
        ["engage", "e.yaml", "--goal", "x", "--exploit-model", "custom:7b"])
    assert args.exploit_model == "custom:7b"
    # planner_model is None from argparse; resolves to DEFAULT_PINS under ollama backend.
    pins = _resolve_pins(planner=args.planner_model, recon=args.recon_model,
                         exploit=args.exploit_model)
    assert pins["planner"] == DEFAULT_PINS["planner"]  # others keep the backend default
    assert pins["exploit"] == "custom:7b"              # explicit flag wins
