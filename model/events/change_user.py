from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import override_relation


machines: dict[str, list[str]] = {"DAC": ["grd1", "grd2"], "DAC_EXT": [], "MAC": []}


def change_user(
    m: Machine, _proc: Machine.ProcsItem | None, _user: Machine.UsersItem | None
) -> Event:

    proc = Parameter(_proc)
    user = Parameter(_user)

    _grd1 = Guard("grd1", lambda _: _(1, (~user) in m.Users))

    _grd2 = Guard("grd2", lambda _: _(2, (~proc) in m.Procs))

    _act = Action(
        "act",
        m,
        "ProcUser",
        lambda: override_relation(m.ProcUser, frozenset((((~proc), (~user)),))),
    )

    return Event("change_user", _grd1, _grd2, _act)
