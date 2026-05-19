from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action


machines: dict[str, list[str]] = { 'MAC': ['grd1'],
             'MAC_EXT': []
}

def set_directory_transmute(m: Machine,
                            _dir: Machine.FilesItem | None) -> Event:

    dir = Parameter(_dir)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~dir) in m.Folders)))


    _act1 = Action('act1', m, 'TransmuteFolders', lambda: ((m.TransmuteFolders | frozenset(((~dir),)))))


    return Event("set_directory_transmute", _grd1, _act1)
