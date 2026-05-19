from model.machine import Machine
from anis.model.lazy import Event, Parameter, Guard, Action
from anis.model.expressions import relation_range, relation_domain, NAT, function_value, relation_image, override_relation


machines: dict[str, list[str]] = { 'DAC': ['grd1', 'grd2', 'grd3', 'grd4', 'grd5', 'grd6', 'grd7', 'grd8', 'grd9', 'grd10', 'grd11', 'grd12', 'grd13', 'grd14', 'grd15', 'grd16', 'grd17', 'grd18', 'grd19', 'grd20', 'grd21', 'grd22', 'grd23'],
             'MAC': ['grd24', 'grd25', 'grd26'],
             'MAC_EXT': ['grd27']
}

def open_create(m: Machine,
                _proc: Machine.ProcsItem | None,
                _parent: Machine.FilesItem | None,
                _file: Machine.FilesItem | None,
                _name: Machine.StringsItem | None,
                _flags: frozenset[int] | None,
                _mode: frozenset[Machine.PermissionsItem] | None,
                _fd: Machine.FileDescriptorsExtendedItem | None,
                _fdNumber: int | None,
                _group: Machine.GroupsItem | None,
                _perms: frozenset[Machine.PermissionsItem] | None,
                _fileLabel: Machine.StringsItem | None) -> Event:

    proc = Parameter(_proc)
    parent = Parameter(_parent)
    file = Parameter(_file)
    name = Parameter(_name)
    flags = Parameter(_flags)
    mode = Parameter(_mode)
    fd = Parameter(_fd)
    fdNumber = Parameter(_fdNumber)
    group = Parameter(_group)
    perms = Parameter(_perms)
    fileLabel = Parameter(_fileLabel)


    _grd1 = Guard('grd1', lambda _: (_(1, 
    (~proc) in m.Procs)))

    _grd2 = Guard('grd2', lambda _: (_(2, 
    (~parent) in m.Folders)))

    _grd3 = Guard('grd3', lambda _: (_(3, 
    (~file) in (((m.FILES - m.Files) - relation_range(m.FDFile)) - relation_range(m.ProcCwd)))))

    _grd4 = Guard('grd4', lambda _: (_(4, 
    not any (True for f in relation_domain(m.FileParents) if not (
        (f, ((~parent), (~name))) not in m.FileParents
    )))))

    _grd5 = Guard('grd5', lambda _: (_(5, 
    (~flags) <= m.OPEN_FLAGS)))

    _grd6 = Guard('grd6', lambda _: (_(6, 
    (~mode) <= m.PERMISSIONS)))

    _grd7 = Guard('grd7', lambda _: (_(7, 
    (~fd) in (m.FILE_DESCRIPTORS - m.FDs))))

    _grd8 = Guard('grd8', lambda _: (_(8, 
    (~fdNumber) in NAT)))

    _grd9 = Guard('grd9', lambda _: (_(9, 
    not any (True for (key, pfd) in m.ProcFDs if key == (~proc) if not (
        function_value(m.FDNumber, pfd) != (~fdNumber)
    )))))

    _grd10 = Guard('grd10', lambda _: ((_(10, 
    m.O_CREAT in (~flags))) or (_(11, m.O_TMPFILE in (~flags)))))

    _grd11 = Guard('grd11', lambda _: (((_(12, 
    m.O_RDONLY in (~flags))) or (_(13, m.O_WRONLY in (~flags)))) or (_(14, m.O_RDWR in (~flags)))))

    _grd12 = Guard('grd12', lambda _: (((not ((_(15, 
    m.O_RDONLY in (~flags))) and (_(16, m.O_WRONLY in (~flags))))) and (not ((_(17, 
    m.O_RDONLY in (~flags))) and (_(18, m.O_RDWR in (~flags)))))) and (not ((_(19, 
    m.O_WRONLY in (~flags))) and (_(20, m.O_RDWR in (~flags)))))))

    _grd13 = Guard('grd13', lambda _: (not (_(21, 
    m.O_TMPFILE in (~flags))) or ((_(22, m.O_WRONLY in (~flags))) or (_(23, m.O_RDWR in (~flags))))))

    _grd14 = Guard('grd14', lambda _: (_(24, 
    len(m.Files) < m.MAX_FILES)))

    _grd15 = Guard('grd15', lambda _: (_(25, 
    len(relation_image(m.ProcFDs, frozenset(((~proc),)))) < m.PROC_FILE_LIMIT)))

    _grd16 = Guard('grd16', lambda _: (_(26, 
    len(relation_range(m.ProcFDs)) < m.FILE_LIMIT)))

    _grd17 = Guard('grd17', lambda _: (_(27, 
    m.O_PATH not in (~flags))))

    _grd18 = Guard('grd18', lambda _: (_(28, 
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

    _grd19 = Guard('grd19', lambda _: (not (_(29, 
    function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) or (((((((_(30, 
    function_value(m.ProcUser, (~proc)) == function_value(m.FileUser, (~parent)))) and (_(31, 
    frozenset((m.UWRITE, m.UEXECUTE)) <= function_value(m.DACPermissions, (~parent))))) or (((((_(32, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and ((_(33, 
    (~parent) not in relation_domain(m.MaskACL))) or (_(34, len(function_value(m.MaskACL, (~parent))) == 0)))) and (_(35, 
    function_value(m.FileGroup, (~parent)) != function_value(m.ProcGroup, (~proc))))) and (_(36, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~parent))) not in m.UserGroups))) and (_(37, 
    frozenset((m.OWRITE, m.OEXECUTE)) <= function_value(m.DACPermissions, (~parent)))))) or ((((_(38, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and (_(39, 
    ((~parent), function_value(m.ProcUser, (~proc))) in relation_domain(m.UserACL)))) and (_(40, frozenset((m.UWRITE, m.UEXECUTE)) <= function_value(m.UserACL, ((~parent), function_value(m.ProcUser, (~proc))))))) and (_(41, 
    frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.MaskACL, (~parent)))))) or (((((_(42, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and (_(43, 
    ((~parent), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(44, 
    any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if 
    (((~parent), g) in relation_domain(m.GroupACL) and frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.GroupACL, ((~parent), g)) or g == function_value(m.FileGroup, (~parent)) and (~parent) in relation_domain(m.GroupObjACL) and frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.GroupObjACL, (~parent))))))) and (_(45, 
    (~parent) in relation_domain(m.MaskACL)))) and (_(46, frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.MaskACL, (~parent)))))) or ((((_(47, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and (_(48, 
    (~parent) not in relation_domain(m.MaskACL)))) and ((_(49, 
    function_value(m.FileGroup, (~parent)) == function_value(m.ProcGroup, (~proc)))) or (_(50, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~parent))) in m.UserGroups)))) and (_(51, 
    frozenset((m.GWRITE, m.GEXECUTE)) <= function_value(m.DACPermissions, (~parent)))))) or ((((((((_(52, 
    function_value(m.ProcUser, (~proc)) != function_value(m.FileUser, (~parent)))) and (_(53, 
    (~parent) in relation_domain(m.MaskACL)))) and (_(54, len(function_value(m.MaskACL, (~parent))) != 0))) and (_(55, 
    ((~parent), function_value(m.ProcUser, (~proc))) not in relation_domain(m.UserACL)))) and (_(56, 
    not any (True for g in (frozenset((function_value(m.ProcGroup, (~proc)),)) | relation_image(m.UserGroups, frozenset((function_value(m.ProcUser, (~proc)),)))) if not (
        ((~parent), g) not in relation_domain(m.GroupACL)
    ))))) and (_(57, 
    function_value(m.FileGroup, (~parent)) != function_value(m.ProcGroup, (~proc))))) and (_(58, (function_value(m.ProcUser, (~proc)), function_value(m.FileGroup, (~parent))) not in m.UserGroups))) and (_(59, 
    frozenset((m.OWRITE, m.OEXECUTE)) <= function_value(m.DACPermissions, (~parent))))))))

    _grd20 = Guard('grd20', lambda _: (_(60, 
    (~group) in m.Groups)))

    _grd21 = Guard('grd21', lambda _: (not (_(61, 
    m.SET_GID not in function_value(m.DACPermissions, (~parent)))) or (_(62, (~group) == function_value(m.ProcGroup, (~proc))))))

    _grd22 = Guard('grd22', lambda _: (not (_(63, 
    m.SET_GID in function_value(m.DACPermissions, (~parent)))) or (_(64, (~group) == function_value(m.FileGroup, (~parent))))))

    _grd23 = Guard('grd23', lambda _: (_(65, 
    (~perms) == ((~mode) - ((~mode) & function_value(m.ProcUmask, (~proc)))))))

    _grd24 = Guard('grd24', lambda _: (not (_(66, function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) or (_(67, 
    not any (True for f in (function_value(m.PathToRoot, (~parent)) | frozenset(((~parent),))) if not (
        not (function_value(m.ProcLabel, (~proc)) == m.STAR) and 
        ((((function_value(m.ProcLabel, (~proc)) == m.HAT or 
        function_value(m.FileLabel, f) == m.FLOOR) or 
        function_value(m.FileLabel, f) == m.STAR) or 
        function_value(m.ProcLabel, (~proc)) == function_value(m.FileLabel, f)) or 
        m.EXECUTE in relation_image(m.SmackRules, frozenset(((function_value(m.ProcLabel, (~proc)), function_value(m.FileLabel, f)),))))
    ))))))

    _grd25 = Guard('grd25', lambda _: (not (_(68, 
    function_value(m.ProcUser, (~proc)) != m.ROOT_USER)) or ((not (_(69, 
    function_value(m.ProcLabel, (~proc)) == m.STAR))) and (((_(70, 
    function_value(m.FileLabel, (~parent)) == m.STAR)) or (_(71, 
    function_value(m.ProcLabel, (~proc)) == function_value(m.FileLabel, (~parent))))) or (_(72, 
    m.WRITE in relation_image(m.SmackRules, frozenset(((function_value(m.ProcLabel, (~proc)), function_value(m.FileLabel, (~parent))),)))))))))

    _grd26 = Guard('grd26', lambda _: ((((_(73, 
    (~parent) in m.TransmuteFolders)) and (_(74, m.TRANSMUTE in relation_image(m.SmackRules, frozenset(((function_value(m.ProcLabel, (~proc)), function_value(m.FileLabel, (~parent))),)))))) and (_(75, 
    (~fileLabel) == function_value(m.FileLabel, (~parent))))) or (_(76, 
    (~fileLabel) == function_value(m.ProcLabel, (~proc))))))

    _grd27 = Guard('grd27', lambda _: (_(77, m.O_DIRECTORY not in (~flags))))


    _act1 = Action('act1', m, 'Files', lambda: ((m.Files | frozenset(((~file),)))))

    _act2 = Action('act2', m, 'FileParents', lambda: ((m.FileParents | frozenset((((~file), ((~parent), (~name))),)))))

    _act3 = Action('act3', m, 'FDs', lambda: ((m.FDs | frozenset(((~fd),)))))

    _act4 = Action('act4', m, 'FDNumber', lambda: (override_relation(m.FDNumber, frozenset((((~fd), (~fdNumber)),)))))

    _act5 = Action('act5', m, 'ProcFDs', lambda: ((m.ProcFDs | frozenset((((~proc), (~fd)),)))))

    _act6 = Action('act6', m, 'FDFlags', lambda: (override_relation(m.FDFlags, frozenset((((~fd), (~flags)),)))))

    _act7 = Action('act7', m, 'FDFile', lambda: (override_relation(m.FDFile, frozenset((((~fd), (~file)),)))))

    _act8 = Action('act8', m, 'DACPermissions', lambda: (override_relation(m.DACPermissions, frozenset((((~file), (~perms)),)))))

    _act9 = Action('act9', m, 'FileUser', lambda: (override_relation(m.FileUser, frozenset((((~file), function_value(m.ProcUser, (~proc))),)))))

    _act10 = Action('act10', m, 'FileGroup', lambda: (override_relation(m.FileGroup, frozenset((((~file), (~group)),)))))

    _act11 = Action('act11', m, 'FileXattrs', lambda: (override_relation(m.FileXattrs, frozenset((((~file), frozenset[tuple[Machine.StringsItem, Machine.DataItem]]()),)))))

    _act12 = Action('act12', m, 'GroupObjACL', lambda: ((m.GroupObjACL | frozenset((((~file), ((~perms) & m.GROUP_PERMISSIONS)),)))))

    _act13 = Action('act13', m, 'FileLabel', lambda: (override_relation(m.FileLabel, frozenset((((~file), (~fileLabel)),)))))


    return Event("open_create", _grd1, _grd2, _grd3, _grd4, _grd5, _grd6, _grd7, _grd8, _grd9, _grd10, _grd11, _grd12, _grd13, _grd14, _grd15, _grd16, _grd17, _grd18, _grd19, _grd20, _grd21, _grd22, _grd23, _grd24, _grd25, _grd26, _grd27, _act1, _act2, _act3, _act4, _act5, _act6, _act7, _act8, _act9, _act10, _act11, _act12, _act13)
