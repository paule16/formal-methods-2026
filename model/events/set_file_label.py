from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import override_relation


machines: dict[str, list[str]] = {"MAC": ["grd1", "grd2"], "MAC_EXT": []}


def set_file_label(
    m: Machine, _file: Machine.FilesItem | None, _label: Machine.StringsItem | None
) -> Event:

    file = Parameter(_file)
    label = Parameter(_label)

    _grd1 = Guard("grd1", lambda _: _(1, (~file) in m.Files))

    _grd2 = Guard("grd2", lambda _: _(2, (~label) in m.STRINGS))

    _act1 = Action(
        "act1",
        m,
        "FileLabel",
        lambda: override_relation(m.FileLabel, frozenset((((~file), (~label)),))),
    )

    return Event("set_file_label", _grd1, _grd2, _act1)
