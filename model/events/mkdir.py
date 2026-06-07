from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import relation_range, relation_domain, function_value, relation_image, override_relation


machines: dict[str, list[str]] = { 'DAC': ['grd1', 'grd2', 'grd3', 'grd4', 'grd5', 'grd6', 'grd7', 'grd8', 'grd9', 'grd10', 'grd11', 'grd12', 'grd13'],
             'MAC': ['grd14', 'grd15'],
             'MAC_EXT': []
}

def mkdir(m: Machine,
          _proc: Machine.ProcsItem | None,
          _parent: Machine.FilesItem | None,
          _folder: Machine.FilesItem | None,
          _name: Machine.StringsItem | None,
          _mode: frozenset[Machine.PermissionsItem] | None,
          _group: Machine.GroupsItem | None,
          _perms: frozenset[Machine.PermissionsItem] | None) -> Event:

    proc = Parameter(_proc)
    parent = Parameter(_parent)
    folder = Parameter(_folder)
    name = Parameter(_name)
    mode = Parameter(_mode)
    group = Parameter(_group)
    perms = Parameter(_perms)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~proc) in m.Procs)))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    (~parent) in m.Folders)))

    _grd3 = Guard('grd3', lambda _: (_(3, 
    (~folder) in ((m.FILES - m.Files) - relation_range(m.FDFile)))))

    _grd4 = Guard('grd4', lambda _: (_(4, 
    not any (True for f in relation_domain(m.FileParents) if not (
        (f, ((~parent), (~name))) not in m.FileParents
    )))))

    _grd5 = Guard('grd5', lambda _: (_(5, 
    (~mode) <= m.PERMISSIONS)))

    _grd6 = Guard('grd6', lambda _: (_(6, 
    (~group) in m.Groups)))

    _grd7 = Guard('grd7', lambda _: (_(7, 
    len(m.Files) < m.MAX_FILES)))

    _grd8 = Guard('grd8', lambda _: (_(8, 
    not any (True for p in m.Procs if not (
        function_value(m.ProcEXE, p) != (~folder)
    )))))

    _grd9 = Guard('grd9', lambda _: (not (_(9, 
    m.SET_GID not in function_value(m.DACPermissions, (~parent)))) or (_(10, (~group) == function_value(m.ProcGroup, (~proc))))))

    _grd10 = Guard('grd10', lambda _: (not (_(11, 
    m.SET_GID in function_value(m.DACPermissions, (~parent)))) or (_(12, (~group) == function_value(m.FileGroup, (~parent))))))

    _grd11 = Guard('grd11', lambda _: (_(13, 
    not any (True for f in function_value(m.PathToRoot, (~parent)) if function_value(m.ProcUser, (~proc)) != m.ROOT_USER if not (
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

    _grd12 = Guard('grd12', lambda _: (not (_(14, 
    function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) or (((((((_(15, 
    function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, (~parent)))) and (_(16, 
    frozenset((m.UWRITE, m.UEXECUTE)) <= function_value(m.DACPermissions, (~parent))))) or (((((_(17, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and ((_(18, 
    (~parent) not in relation_domain(m.MaskACL))) or (_(19, len(function_value(m.MaskACL, (~parent))) == 0)))) and (_(20, 
    function_value(m.FileGroup, (~parent)) != function_value(m.ProcGroup, (~proc))))) and (_(21, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~parent))) not in m.UserGroups))) and (_(22, 
    frozenset((m.OWRITE, m.OEXECUTE)) <= function_value(m.DACPermissions, (~parent)))))) or ((((_(23, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and (_(24, 
    ((~parent), function_value(m.ProcUser, (~proc))) in relation_domain(m.UserACL)))) and (_(25, frozenset((m.UWRITE, m.UEXECUTE)) <= function_value(m.UserACL, ((~parent), function_value(m.ProcUser, (~proc))))))) and (_(26, 
    frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.MaskACL, (~parent)))))) or (((((_(27, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and (_(28, 
    ((~parent), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(29, 
    any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if 
    (((~parent), g) in relation_domain(m.GroupACL) and frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.GroupACL, ((~parent), g)) or g == function_value(m.FileGroup, (~parent)) and (~parent) in relation_domain(m.GroupObjACL) and frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.GroupObjACL, (~parent))))))) and (_(30, 
    (~parent) in relation_domain(m.MaskACL)))) and (_(31, frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.MaskACL, (~parent)))))) or ((((_(32, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and (_(33, 
    (~parent) not in relation_domain(m.MaskACL)))) and ((_(34, 
    function_value(m.FileGroup, (~parent)) == function_value(m.ProcGroup, (~proc)))) or (_(35, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~parent))) in m.UserGroups)))) and (_(36, 
    frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.DACPermissions, (~parent)))))) or ((((((((_(37, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and (_(38, 
    (~parent) in relation_domain(m.MaskACL)))) and (_(39, len(function_value(m.MaskACL, (~parent))) != 0))) and (_(40, 
    ((~parent), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(41, 
    not any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if not (
        ((~parent), g) not in relation_domain(m.GroupACL)
    ))))) and (_(42, 
    function_value(m.FileGroup, (~parent)) != function_value(m.ProcGroup, (~proc))))) and (_(43, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~parent))) not in m.UserGroups))) and (_(44, 
    frozenset((m.OWRITE, m.OEXECUTE)) <= function_value(m.DACPermissions, (~parent))))))))

    _grd13 = Guard('grd13', lambda _: (_(45, 
    (~perms) == (((~mode) | (function_value(m.DACPermissions, (~parent)) & frozenset((m.SET_GID,)))) - ((~mode) & function_value(m.ProcUmask, (~proc)))))))

    _grd14 = Guard('grd14', lambda _: (not (_(46, function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) or (_(47, 
    not any (True for f in (function_value(m.PathToRoot, (~parent)) | frozenset(((~parent),))) if not (
        not (function_value(m.ProcLabel, (~proc)) == m.STAR) and 
        ((((function_value(m.ProcLabel, (~proc)) == m.HAT or 
        function_value(m.FileLabel, f) == m.FLOOR) or 
        function_value(m.FileLabel, f) == m.STAR) or 
        function_value(m.ProcLabel, (~proc)) == function_value(m.FileLabel, f)) or 
        m.EXECUTE in relation_image(m.SmackRules, frozenset(((function_value(m.ProcLabel, (~proc)), function_value(m.FileLabel, f)),))))
    ))))))

    _grd15 = Guard('grd15', lambda _: (not (_(48, 
    function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) or ((not (_(49, 
    function_value(m.ProcLabel, (~proc)) == m.STAR))) and (((_(50, 
    function_value(m.FileLabel, (~parent)) == m.STAR)) or (_(51, 
    function_value(m.ProcLabel, (~proc)) == function_value(m.FileLabel, (~parent))))) or (_(52, 
    m.WRITE in relation_image(m.SmackRules, frozenset(((function_value(m.ProcLabel, (~proc)), function_value(m.FileLabel, (~parent))),)))))))))


    _act1 = Action('act1', m, 'Files', lambda: ((m.Files | frozenset(((~folder),)))))

    _act2 = Action('act2', m, 'Folders', lambda: ((m.Folders | frozenset(((~folder),)))))

    _act3 = Action('act3', m, 'FileParents', lambda: ((m.FileParents | frozenset((((~folder), ((~parent), (~name))),)))))

    _act4 = Action('act4', m, 'PathToRoot', lambda: (override_relation(m.PathToRoot, frozenset((((~folder), (function_value(m.PathToRoot, (~parent)) | frozenset(((~parent),)))),)))))

    _act5 = Action('act5', m, 'DACPermissions', lambda: (override_relation(m.DACPermissions, frozenset((((~folder), (~perms)),)))))

    _act6 = Action('act6', m, 'FileUser', lambda: (override_relation(m.FileUser, frozenset((((~folder), function_value(m.ProcUser, (~proc))),)))))

    _act7 = Action('act7', m, 'FileGroup', lambda: (override_relation(m.FileGroup, frozenset((((~folder), (~group)),)))))

    _act8 = Action('act8', m, 'FileXattrs', lambda: (override_relation(m.FileXattrs, frozenset((((~folder), frozenset[tuple[Machine.StringsItem, Machine.DataItem]]()),)))))

    _act9 = Action('act9', m, 'GroupObjACL', lambda: ((m.GroupObjACL | frozenset((((~folder), ((~perms) & m.GROUP_PERMISSIONS)),)))))

    _act10 = Action('act10', m, 'FileLabel', lambda: (override_relation(m.FileLabel, frozenset((((~folder), function_value(m.ProcLabel, (~proc))),)))))


    return Event("mkdir", _grd1, _grd2, _grd3, _grd4, _grd5, _grd6, _grd7, _grd8, _grd9, _grd10, _grd11, _grd12, _grd13, _grd14, _grd15, _act1, _act2, _act3, _act4, _act5, _act6, _act7, _act8, _act9, _act10)
