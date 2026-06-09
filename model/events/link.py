from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import relation_range, function_value, relation_domain, relation_image


machines: dict[str, list[str]] = { 'DAC': ['grd1', 'grd2', 'grd3', 'grd4', 'grd5', 'grd6', 'grd7', 'grd8', 'grd9', 'grd10'],
             'DAC_EXT': [],
             'MAC': ['grd11', 'grd12', 'grd13', 'grd14', 'grd15']
}

def link(m: Machine,
         _proc: Machine.ProcsItem | None,
         _oldParent: Machine.FilesItem | None,
         _newParent: Machine.FilesItem | None,
         _file: Machine.FilesItem | None,
         _oldName: Machine.StringsItem | None,
         _newName: Machine.StringsItem | None) -> Event:

    proc = Parameter(_proc)
    oldParent = Parameter(_oldParent)
    newParent = Parameter(_newParent)
    file = Parameter(_file)
    oldName = Parameter(_oldName)
    newName = Parameter(_newName)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~proc) in m.Procs)))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    (~oldParent) in m.Folders)))

    _grd3 = Guard('grd3', lambda _: (_(3, 
    (~newParent) in m.Folders)))

    _grd4 = Guard('grd4', lambda _: (_(4, 
    (~file) in (m.Files - m.Folders))))

    _grd5 = Guard('grd5', lambda _: (_(5, 
    ((~file), ((~oldParent), (~oldName))) in m.FileParents)))

    _grd6 = Guard('grd6', lambda _: (_(6, 
    ((~newParent), (~newName)) not in relation_range(m.FileParents))))

    _grd7 = Guard('grd7', lambda _: (_(7, 
    not any (True for f in (function_value(m.PathToRoot, (~oldParent)) | frozenset(((~oldParent),))) if function_value(m.ProcUser, (~proc)) != m.ROOT_USER if not (
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

    _grd8 = Guard('grd8', lambda _: (_(8, 
    not any (True for f in function_value(m.PathToRoot, (~newParent)) if function_value(m.ProcUser, (~proc)) != m.ROOT_USER if not (
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

    _grd9 = Guard('grd9', lambda _: (not (_(9, 
    function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) or (((((((_(10, 
    function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, (~newParent)))) and (_(11, 
    frozenset((m.UWRITE, m.UEXECUTE)) <= function_value(m.DACPermissions, (~newParent))))) or (((((_(12, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~newParent)))) and ((_(13, 
    (~newParent) not in relation_domain(m.MaskACL))) or (_(14, len(function_value(m.MaskACL, (~newParent))) == 0)))) and (_(15, 
    function_value(m.FileGroup, (~newParent)) != function_value(m.ProcGroup, (~proc))))) and (_(16, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~newParent))) not in m.UserGroups))) and (_(17, 
    frozenset((m.OWRITE, m.OEXECUTE)) <= function_value(m.DACPermissions, (~newParent)))))) or ((((_(18, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~newParent)))) and (_(19, 
    ((~newParent), function_value(m.ProcUser, (~proc))) in relation_domain(m.UserACL)))) and (_(20, frozenset((m.UWRITE, m.UEXECUTE)) <= function_value(m.UserACL, ((~newParent), function_value(m.ProcUser, (~proc))))))) and (_(21, 
    frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.MaskACL, (~newParent)))))) or (((((_(22, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~newParent)))) and (_(23, 
    ((~newParent), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(24, 
    any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if 
    (((~newParent), g) in relation_domain(m.GroupACL) and frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.GroupACL, ((~newParent), g)) or g == function_value(m.FileGroup, (~newParent)) and (~newParent) in relation_domain(m.GroupObjACL) and frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.GroupObjACL, (~newParent))))))) and (_(25, 
    (~newParent) in relation_domain(m.MaskACL)))) and (_(26, frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.MaskACL, (~newParent)))))) or ((((_(27, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~newParent)))) and (_(28, 
    (~newParent) not in relation_domain(m.MaskACL)))) and ((_(29, 
    function_value(m.FileGroup, (~newParent)) == function_value(m.ProcGroup, (~proc)))) or (_(30, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~newParent))) in m.UserGroups)))) and (_(31, 
    frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.DACPermissions, (~newParent)))))) or ((((((((_(32, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~newParent)))) and (_(33, 
    (~newParent) in relation_domain(m.MaskACL)))) and (_(34, len(function_value(m.MaskACL, (~newParent))) != 0))) and (_(35, 
    ((~newParent), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(36, 
    not any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if not (
        ((~newParent), g) not in relation_domain(m.GroupACL)
    ))))) and (_(37, 
    function_value(m.FileGroup, (~newParent)) != function_value(m.ProcGroup, (~proc))))) and (_(38, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~newParent))) not in m.UserGroups))) and (_(39, 
    frozenset((m.OWRITE, m.OEXECUTE)) <= function_value(m.DACPermissions, (~newParent))))))))

    _grd10 = Guard('grd10', lambda _: (not (_(40, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) or (((((((_(41, 
    function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, (~file)))) and (_(42, 
    frozenset((m.UREAD, m.UWRITE)) <= function_value(m.DACPermissions, (~file))))) or (((((_(43, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and ((_(44, 
    (~file) not in relation_domain(m.MaskACL))) or (_(45, len(function_value(m.MaskACL, (~file))) == 0)))) and (_(46, 
    function_value(m.FileGroup, (~file)) != function_value(m.ProcGroup, (~proc))))) and (_(47, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) not in m.UserGroups))) and (_(48, 
    frozenset((m.OREAD, m.OWRITE)) <= function_value(m.DACPermissions, (~file)))))) or ((((_(49, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(50, 
    ((~file), function_value(m.ProcUser, (~proc))) in relation_domain(m.UserACL)))) and (_(51, frozenset((m.UREAD, m.UWRITE)) <= function_value(m.UserACL, ((~file), function_value(m.ProcUser, (~proc))))))) and (_(52, 
    frozenset((m.GREAD, m.GWRITE)) <= function_value(m.MaskACL, (~file)))))) or (((((_(53, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(54, 
    ((~file), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(55, 
    any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if 
    (((~file), g) in relation_domain(m.GroupACL) and frozenset((m.GREAD, m.GWRITE)) <= function_value(m.GroupACL, ((~file), g)) or g == function_value(m.FileGroup, (~file)) and (~file) in relation_domain(m.GroupObjACL) and frozenset((m.GREAD, m.GWRITE)) <= function_value(m.GroupObjACL, (~file))))))) and (_(56, 
    (~file) in relation_domain(m.MaskACL)))) and (_(57, frozenset((m.GREAD, m.GWRITE)) <= function_value(m.MaskACL, (~file)))))) or ((((_(58, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(59, 
    (~file) not in relation_domain(m.MaskACL)))) and ((_(60, 
    function_value(m.FileGroup, (~file)) == function_value(m.ProcGroup, (~proc)))) or (_(61, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) in m.UserGroups)))) and (_(62, 
    frozenset((m.GREAD, m.GWRITE)) <= function_value(m.DACPermissions, (~file)))))) or ((((((((_(63, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~file)))) and (_(64, 
    (~file) in relation_domain(m.MaskACL)))) and (_(65, len(function_value(m.MaskACL, (~file))) != 0))) and (_(66, 
    ((~file), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(67, 
    not any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if not (
        ((~file), g) not in relation_domain(m.GroupACL)
    ))))) and (_(68, 
    function_value(m.FileGroup, (~file)) != function_value(m.ProcGroup, (~proc))))) and (_(69, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~file))) not in m.UserGroups))) and (_(70, 
    frozenset((m.OREAD, m.OWRITE)) <= function_value(m.DACPermissions, (~file))))))))

    _grd11 = Guard('grd11', lambda _: (not (_(71, function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) or (_(72, 
    not any (True for f in (function_value(m.PathToRoot, (~oldParent)) | frozenset(((~oldParent),))) if not (
        not (function_value(m.ProcLabel, (~proc)) == m.STAR) and 
        ((((function_value(m.ProcLabel, (~proc)) == m.HAT or 
        function_value(m.FileLabel, f) == m.FLOOR) or 
        function_value(m.FileLabel, f) == m.STAR) or 
        function_value(m.ProcLabel, (~proc)) == function_value(m.FileLabel, f)) or 
        m.EXECUTE in relation_image(m.SmackRules, frozenset(((function_value(m.ProcLabel, (~proc)), function_value(m.FileLabel, f)),))))
    ))))))

    _grd12 = Guard('grd12', lambda _: (not (_(73, 
    function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) or (_(74, 
    not any (True for f in (function_value(m.PathToRoot, (~newParent)) | frozenset(((~newParent),))) if not (
        not (function_value(m.ProcLabel, (~proc)) == m.STAR) and 
        ((((function_value(m.ProcLabel, (~proc)) == m.HAT or 
        function_value(m.FileLabel, f) == m.FLOOR) or 
        function_value(m.FileLabel, f) == m.STAR) or 
        function_value(m.ProcLabel, (~proc)) == function_value(m.FileLabel, f)) or 
        m.EXECUTE in relation_image(m.SmackRules, frozenset(((function_value(m.ProcLabel, (~proc)), function_value(m.FileLabel, f)),))))
    ))))))

    _grd13 = Guard('grd13', lambda _: (not (_(75, 
    function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) or ((not (_(76, 
    function_value(m.ProcLabel, (~proc)) == m.STAR))) and (((_(77, 
    function_value(m.FileLabel, (~newParent)) == m.STAR)) or (_(78, 
    function_value(m.ProcLabel, (~proc)) == function_value(m.FileLabel, (~newParent))))) or (_(79, 
    m.WRITE in relation_image(m.SmackRules, frozenset(((function_value(m.ProcLabel, (~proc)), function_value(m.FileLabel, (~newParent))),)))))))))

    _grd14 = Guard('grd14', lambda _: (not (_(80, 
    function_value(m.ProcUser, (~proc)) not in frozenset((function_value(m.FileUser, (~file)), m.ROOT_USER)))) or ((not (_(81, 
    function_value(m.ProcLabel, (~proc)) == m.STAR))) and (((((_(82, 
    function_value(m.ProcLabel, (~proc)) == m.HAT)) or (_(83, 
    function_value(m.FileLabel, (~file)) == m.FLOOR))) or (_(84, 
    function_value(m.FileLabel, (~file)) == m.STAR))) or (_(85, 
    function_value(m.ProcLabel, (~proc)) == function_value(m.FileLabel, (~file))))) or (_(86, 
    m.READ in relation_image(m.SmackRules, frozenset(((function_value(m.ProcLabel, (~proc)), function_value(m.FileLabel, (~file))),)))))))))

    _grd15 = Guard('grd15', lambda _: (not (_(87, 
    function_value(m.ProcUser, (~proc)) not in frozenset((function_value(m.FileUser, (~file)), m.ROOT_USER)))) or ((not (_(88, 
    function_value(m.ProcLabel, (~proc)) == m.STAR))) and (((_(89, 
    function_value(m.FileLabel, (~file)) == m.STAR)) or (_(90, 
    function_value(m.ProcLabel, (~proc)) == function_value(m.FileLabel, (~file))))) or (_(91, 
    m.WRITE in relation_image(m.SmackRules, frozenset(((function_value(m.ProcLabel, (~proc)), function_value(m.FileLabel, (~file))),)))))))))


    _act1 = Action('act1', m, 'FileParents', lambda: ((m.FileParents | frozenset((((~file), ((~newParent), (~newName))),)))))


    return Event("link", _grd1, _grd2, _grd3, _grd4, _grd5, _grd6, _grd7, _grd8, _grd9, _grd10, _grd11, _grd12, _grd13, _grd14, _grd15, _act1)
