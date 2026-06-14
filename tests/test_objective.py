from grin.objective import Objective


def test_objective_holds_goal_and_target():
    o = Objective(objective="enumerate hosts in 203.0.113.0/24", target="203.0.113.0/24")
    assert o.objective == "enumerate hosts in 203.0.113.0/24"
    assert o.target == "203.0.113.0/24"


def test_objective_is_value_equal():
    a = Objective(objective="scan web", target="203.0.113.7")
    b = Objective(objective="scan web", target="203.0.113.7")
    assert a == b
