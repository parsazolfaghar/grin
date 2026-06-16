from grin.strength import STRENGTH_LEVELS, strength_params, StrengthParams


def test_levels():
    assert STRENGTH_LEVELS == ("recon", "normal", "aggressive", "max")


def test_recon():
    p = strength_params("recon")
    assert isinstance(p, StrengthParams)
    assert p.aggressive is False and p.recon_only is True
    assert p.max_objectives == 5 and p.max_steps == 8


def test_normal():
    p = strength_params("normal")
    assert p.aggressive is False and p.recon_only is False
    assert p.max_objectives == 10 and p.max_steps == 12


def test_aggressive():
    p = strength_params("aggressive")
    assert p.aggressive is True and p.recon_only is False
    assert p.max_objectives == 24 and p.max_steps == 12


def test_max():
    p = strength_params("max")
    assert p.aggressive is True and p.max_objectives == 40 and p.max_steps == 20


def test_unknown_falls_back_to_normal():
    assert strength_params("bogus") == strength_params("normal")
