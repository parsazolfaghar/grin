from grin.cli import build_parser, DEFAULT_PINS


def test_engage_defaults_to_recommended_pins():
    args = build_parser().parse_args(["engage", "e.yaml", "--goal", "x"])
    assert args.planner_model == DEFAULT_PINS["planner"]
    assert args.recon_model == DEFAULT_PINS["recon"]
    assert args.exploit_model == DEFAULT_PINS["exploit"]


def test_pins_are_overridable():
    args = build_parser().parse_args(
        ["engage", "e.yaml", "--goal", "x", "--exploit-model", "custom:7b"])
    assert args.exploit_model == "custom:7b"
    assert args.planner_model == DEFAULT_PINS["planner"]  # others keep the default
