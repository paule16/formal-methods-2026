from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import function_value, relation_domain, relation_image, override_relation


machines: dict[str, list[str]] = { 'DAC': ['grd1', 'grd2', 'grd3'],
             'MAC': ['grd4'],
             'MAC_EXT': []
}

def chdir(m: Machine,
          _proc: Machine.ProcsItem | None,
          _dir: Machine.FilesItem | None) -> Event:

    proc = Parameter(_proc)
    dir = Parameter(_dir)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~proc) in m.Procs)))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    (~dir) in m.Folders)))

    _grd3 = Guard('grd3', lambda _: (_(3, 
    not any (True for f in (function_value(m.PathToRoot, (~dir)) | frozenset(((~dir),))) if function_value(m.ProcUser, (~proc)) != m.ROOT_USER if not (
        (((((function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, f) and 
        m.UEXECUTE in function_value(m.DACPermissions, f) or 
        function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, f) and 
        (f not in relation_domain(m.MaskACL) or len(function_value(m.MaskACL, f)) == 0) and 
        function_value(m.FileGroup, f) != function_value(m.ProcGroup, (~proc)) and (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, f)) not in m.UserGroups and 
        m.OEXECUTE in function_value(m.DACPermissions, f)) or 
        function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, f) and 
        (f, function_value(m.ProcUser, (~proc))) in relation_domain(m.UserACL) and m.UEXECUTE in function_value(m.UserACL, (f, function_value(m.ProcUser, (~proc)))) and 
        m.GEXECUTE in function_value(m.MaskACL, f)) or 
        function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, f) and 
        (f, function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL) and 
        any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if 
        ((f, g) in relation_domain(m.GroupACL) and m.GEXECUTE in function_value(m.GroupACL, (f, g)) or g == function_value(m.FileGroup, f) and f in relation_domain(m.GroupObjACL) and m.GEXECUTE in function_value(m.GroupObjACL, f))) and 
        f in relation_domain(m.MaskACL) and m.GEXECUTE in function_value(m.MaskACL, f)) or 
        function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, f) and 
        f not in relation_domain(m.MaskACL) and 
        (function_value(m.FileGroup, f) == function_value(m.ProcGroup, (~proc)) or (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, f)) in m.UserGroups) and 
        m.GEXECUTE in function_value(m.DACPermissions, f)) or 
        function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, f) and 
        f in relation_domain(m.MaskACL) and len(function_value(m.MaskACL, f)) != 0 and 
        (f, function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL) and 
        not any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if not (
            (f, g) not in relation_domain(m.GroupACL)
        )) and 
        function_value(m.FileGroup, f) != function_value(m.ProcGroup, (~proc)) and (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, f)) not in m.UserGroups and 
        m.OEXECUTE in function_value(m.DACPermissions, f))
    )))))

    _grd4 = Guard('grd4', lambda _: (not (_(4, function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) or (_(5, 
    not any (True for f in (function_value(m.PathToRoot, (~dir)) | frozenset(((~dir),))) if not (
        not (function_value(m.ProcLabel, (~proc)) == m.STAR) and 
        ((((function_value(m.ProcLabel, (~proc)) == m.HAT or 
        function_value(m.FileLabel, f) == m.FLOOR) or 
        function_value(m.FileLabel, f) == m.STAR) or 
        function_value(m.ProcLabel, (~proc)) == function_value(m.FileLabel, f)) or 
        m.EXECUTE in relation_image(m.SmackRules, frozenset(((function_value(m.ProcLabel, (~proc)), function_value(m.FileLabel, f)),))))
    ))))))


    _act1 = Action('act1', m, 'ProcCwd', lambda: (override_relation(m.ProcCwd, frozenset((((~proc), (~dir)),)))))


    return Event("chdir", _grd1, _grd2, _grd3, _grd4, _act1)
