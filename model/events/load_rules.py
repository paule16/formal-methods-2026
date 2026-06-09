from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import cartesian_product


machines: dict[str, list[str]] = { 'MAC': ['grd1']
}

def load_rules(m: Machine,
               _rules: frozenset[tuple[tuple[Machine.StringsItem, Machine.StringsItem], Machine.AccessesItem]] | None) -> Event:

    rules = Parameter(_rules)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~rules) <= cartesian_product(cartesian_product(m.STRINGS, m.STRINGS), m.ACCESSES))))


    _act1 = Action('act1', m, 'SmackRules', lambda: ((m.SmackRules | (~rules))))


    return Event("load_rules", _grd1, _act1)
