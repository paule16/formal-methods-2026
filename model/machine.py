from anis.model.expressions import CarrierSetItem, carrier_set
from collections.abc import Set


class Machine:
    class FilesItem(CarrierSetItem): pass
    class ProcsItem(CarrierSetItem): pass
    class UsersItem(CarrierSetItem): pass
    class GroupsItem(CarrierSetItem): pass
    class FileDescriptorsExtendedItem(CarrierSetItem): pass
    class PermissionsItem(CarrierSetItem): pass
    class StringsItem(CarrierSetItem): pass
    class DataItem(CarrierSetItem): pass
    class CapabilitiesItem(CarrierSetItem): pass
    class AccessesItem(CarrierSetItem): pass
    class XattrFlagsItem(CarrierSetItem): pass
    class IntegrityModesItem(CarrierSetItem): pass
    class HashesItem(CarrierSetItem): pass

    INIT: ProcsItem
    INIT_EXE: FilesItem
    INIT_NAME: StringsItem
    ROOT: FilesItem
    MAX_FILES: int
    PROC_FILE_LIMIT: int
    FILE_LIMIT: int
    USER_PERMISSIONS: Set[PermissionsItem]
    GROUP_PERMISSIONS: Set[PermissionsItem]
    OTHER_PERMISSIONS: Set[PermissionsItem]
    FILE_MODES: Set[PermissionsItem]
    UREAD: PermissionsItem
    UWRITE: PermissionsItem
    UEXECUTE: PermissionsItem
    GREAD: PermissionsItem
    GWRITE: PermissionsItem
    GEXECUTE: PermissionsItem
    OREAD: PermissionsItem
    OWRITE: PermissionsItem
    OEXECUTE: PermissionsItem
    SET_UID: PermissionsItem
    SET_GID: PermissionsItem
    STICKY_BIT: PermissionsItem
    DEF_FILE_PERMS: Set[PermissionsItem]
    DEF_FOLDER_PERMS: Set[PermissionsItem]
    DEF_SYMLINK_PERMS: Set[PermissionsItem]
    ROOT_USER: UsersItem
    ROOT_GROUP: GroupsItem
    FILE_DESCRIPTORS: Set[FileDescriptorsExtendedItem]
    AT_FDCWD: FileDescriptorsExtendedItem
    RESERVED_LABELS: Set[StringsItem]
    FLOOR: StringsItem
    HAT: StringsItem
    STAR: StringsItem
    HUH: StringsItem
    WEB: StringsItem
    INIT_LABEL: StringsItem
    ROOT_LABEL: StringsItem
    INIT_EXE_LABEL: StringsItem
    READ: AccessesItem
    WRITE: AccessesItem
    EXECUTE: AccessesItem
    TRANSMUTE: AccessesItem
    CAP_MAC_ADMIN: CapabilitiesItem
    CAP_MAC_OVERRIDE: CapabilitiesItem
    OPEN_FLAGS: Set[int]
    O_RDONLY: int
    O_WRONLY: int
    O_RDWR: int
    O_CREAT: int
    O_EXCL: int
    O_DIRECT: int
    O_TMPFILE: int
    O_DIRECTORY: int
    O_CLOEXEC: int
    O_NOCTTY: int
    O_NOFOLLOW: int
    O_TRUNC: int
    O_APPEND: int
    O_ASYNC: int
    O_SYNC: int
    O_DSYNC: int
    O_NOATIME: int
    O_LARGEFILE: int
    O_PATH: int
    O_NOBLOCK: int
    O_NDELAY: int
    XATTR_CREATE: XattrFlagsItem
    XATTR_REPLACE: XattrFlagsItem
    ENFORCE: IntegrityModesItem
    FIX: IntegrityModesItem
    OFF: IntegrityModesItem
    IMA_STRING: StringsItem
    EVM_STRING: StringsItem
    S_IRUSR: PermissionsItem
    S_IWUSR: PermissionsItem
    S_IXUSR: PermissionsItem
    S_IRGRP: PermissionsItem
    S_IWGRP: PermissionsItem
    S_IXGRP: PermissionsItem
    S_IROTH: PermissionsItem
    S_IWOTH: PermissionsItem
    S_IXOTH: PermissionsItem
    S_ISUID: PermissionsItem
    S_ISGID: PermissionsItem
    S_ISVTX: PermissionsItem

    # @act1: Users ≔ {ROOT_USER}
    Users: Set[UsersItem]
    # @act2: Groups ≔ {ROOT_GROUP}
    Groups: Set[GroupsItem]
    # @act3: Procs ≔ {INIT}
    Procs: Set[ProcsItem]
    # @act4: Files ≔ {ROOT, INIT_EXE}
    Files: Set[FilesItem]
    # @act5: Folders ≔ {ROOT}
    Folders: Set[FilesItem]
    # @act6: SymLinks ≔ ∅
    SymLinks: Set[FilesItem]
    # @act7: FDs ≔ ∅
    FDs: Set[FileDescriptorsExtendedItem]
    # @act8: FileParents ≔ {INIT_EXE ↦ (ROOT ↦ INIT_NAME)}
    FileParents: Set[tuple[FilesItem, tuple[FilesItem, StringsItem]]]
    # @act9: FileLink ≔ ∅
    FileLink: Set[tuple[FilesItem, tuple[FilesItem, StringsItem]]]
    # @act10: ProcFDs ≔ ∅
    ProcFDs: Set[tuple[ProcsItem, FileDescriptorsExtendedItem]]
    # @act11: FDFlags ≔ ∅
    FDFlags: Set[tuple[FileDescriptorsExtendedItem, frozenset[int]]]
    # @act12: FDFile ≔ ∅
    FDFile: Set[tuple[FileDescriptorsExtendedItem, FilesItem]]
    # @act13: FDNumber ≔ ∅
    FDNumber: Set[tuple[FileDescriptorsExtendedItem, int]]
    # @act14: DACPermissions ≔ {ROOT ↦ DEF_FOLDER_PERMS, INIT_EXE ↦ DEF_FILE_PERMS}
    DACPermissions: Set[tuple[FilesItem, frozenset[PermissionsItem]]]
    # @act15: UserACL ≔ ∅
    UserACL: Set[tuple[tuple[FilesItem, UsersItem], frozenset[PermissionsItem]]]
    # @act16: GroupACL ≔ ∅
    GroupACL: Set[tuple[tuple[FilesItem, GroupsItem], frozenset[PermissionsItem]]]
    # @act17: GroupObjACL ≔ {ROOT ↦ DEF_FOLDER_PERMS ∩ GROUP_PERMISSIONS, INIT_EXE ↦ DEF_FILE_PERMS ∩ GROUP_PERMISSIONS}
    GroupObjACL: Set[tuple[FilesItem, frozenset[PermissionsItem]]]
    # @act18: MaskACL ≔ ∅
    MaskACL: Set[tuple[FilesItem, frozenset[PermissionsItem]]]
    # @act19: FileUser ≔ {ROOT ↦ ROOT_USER, INIT_EXE ↦ ROOT_USER}
    FileUser: Set[tuple[FilesItem, UsersItem]]
    # @act20: FileGroup ≔ {ROOT ↦ ROOT_GROUP, INIT_EXE ↦ ROOT_GROUP}
    FileGroup: Set[tuple[FilesItem, GroupsItem]]
    # @act21: ProcUser ≔ {INIT ↦ ROOT_USER}
    ProcUser: Set[tuple[ProcsItem, UsersItem]]
    # @act22: ProcGroup ≔ {INIT ↦ ROOT_GROUP}
    ProcGroup: Set[tuple[ProcsItem, GroupsItem]]
    # @act23: ProcUmask ≔ {INIT ↦ ∅}
    ProcUmask: Set[tuple[ProcsItem, frozenset[PermissionsItem]]]
    # @act24: FileXattrs ≔ {ROOT ↦ ∅, INIT_EXE ↦ ∅}
    FileXattrs: Set[tuple[FilesItem, frozenset[tuple[StringsItem, DataItem]]]]
    # @act25: ProcEXE ≔ {INIT ↦ INIT_EXE}
    ProcEXE: Set[tuple[ProcsItem, FilesItem]]
    # @act26: ProcArgv ≔ {INIT ↦ ∅}
    ProcArgv: Set[tuple[ProcsItem, frozenset[StringsItem]]]
    # @act27: ProcEnvp ≔ {INIT ↦ ∅}
    ProcEnvp: Set[tuple[ProcsItem, frozenset[StringsItem]]]
    # @act28: ProcCwd ≔ {INIT ↦ ROOT}
    ProcCwd: Set[tuple[ProcsItem, FilesItem]]
    # @act29: ProcParent ≔ ∅
    ProcParent: Set[tuple[ProcsItem, ProcsItem]]
    # @act30: UserGroups ≔ {ROOT_USER ↦ ROOT_GROUP}
    UserGroups: Set[tuple[UsersItem, GroupsItem]]
    # @act31: PathToRoot ≔ {ROOT ↦ ∅}
    PathToRoot: Set[tuple[FilesItem, frozenset[FilesItem]]]
    # @act32: UserCaps ≔ {ROOT_USER ↦ ∅}
    UserCaps: Set[tuple[UsersItem, frozenset[CapabilitiesItem]]]
    # @act33: ProcLabel ≔ {INIT ↦ INIT_LABEL}
    ProcLabel: Set[tuple[ProcsItem, StringsItem]]
    # @act34: FileLabel ≔ {ROOT ↦ ROOT_LABEL, INIT_EXE ↦ INIT_EXE_LABEL}
    FileLabel: Set[tuple[FilesItem, StringsItem]]
    # @act35: SmackRules ≔ ∅
    SmackRules: Set[tuple[tuple[StringsItem, StringsItem], AccessesItem]]
    # @act36: FileExecLabel ≔ ∅
    FileExecLabel: Set[tuple[FilesItem, StringsItem]]
    # @act37: TransmuteFolders ≔ ∅
    TransmuteFolders: Set[FilesItem]

    def __init__(self):
        self.FILES = carrier_set('FILES', self, Machine.FilesItem)
        self.PROCS = carrier_set('PROCS', self, Machine.ProcsItem)
        self.USERS = carrier_set('USERS', self, Machine.UsersItem)
        self.GROUPS = carrier_set('GROUPS', self, Machine.GroupsItem)
        self.FILE_DESCRIPTORS_EXTENDED = carrier_set('FILE_DESCRIPTORS_EXTENDED', self, Machine.FileDescriptorsExtendedItem)
        self.PERMISSIONS = carrier_set('PERMISSIONS', self, Machine.PermissionsItem)
        self.STRINGS = carrier_set('STRINGS', self, Machine.StringsItem)
        self.DATA = carrier_set('DATA', self, Machine.DataItem)
        self.CAPABILITIES = carrier_set('CAPABILITIES', self, Machine.CapabilitiesItem)
        self.ACCESSES = carrier_set('ACCESSES', self, Machine.AccessesItem)
        self.XATTR_FLAGS = carrier_set('XATTR_FLAGS', self, Machine.XattrFlagsItem)
        self.INTEGRITY_MODES = carrier_set('INTEGRITY_MODES', self, Machine.IntegrityModesItem)
        self.HASHES = carrier_set('HASHES', self, Machine.HashesItem)

        self.USER_PERMISSIONS = frozenset()  # pyright: ignore[reportConstantRedefinition]}
        self.GROUP_PERMISSIONS = frozenset()  # pyright: ignore[reportConstantRedefinition]}
        self.OTHER_PERMISSIONS = frozenset()  # pyright: ignore[reportConstantRedefinition]}
        self.FILE_MODES = frozenset()  # pyright: ignore[reportConstantRedefinition]}
        self.DEF_FILE_PERMS = frozenset()  # pyright: ignore[reportConstantRedefinition]}
        self.DEF_FOLDER_PERMS = frozenset()  # pyright: ignore[reportConstantRedefinition]}
        self.DEF_SYMLINK_PERMS = frozenset()  # pyright: ignore[reportConstantRedefinition]}
        self.FILE_DESCRIPTORS = frozenset()  # pyright: ignore[reportConstantRedefinition]}
        self.RESERVED_LABELS = frozenset()  # pyright: ignore[reportConstantRedefinition]}
        self.OPEN_FLAGS = frozenset()  # pyright: ignore[reportConstantRedefinition]}

        self.Users = frozenset()
        self.Groups = frozenset()
        self.Procs = frozenset()
        self.Files = frozenset()
        self.Folders = frozenset()
        self.SymLinks = frozenset()
        self.FDs = frozenset()
        self.FileParents = frozenset()
        self.FileLink = frozenset()
        self.ProcFDs = frozenset()
        self.FDFlags = frozenset()
        self.FDFile = frozenset()
        self.FDNumber = frozenset()
        self.DACPermissions = frozenset()
        self.UserACL = frozenset()
        self.GroupACL = frozenset()
        self.GroupObjACL = frozenset()
        self.MaskACL = frozenset()
        self.FileUser = frozenset()
        self.FileGroup = frozenset()
        self.ProcUser = frozenset()
        self.ProcGroup = frozenset()
        self.ProcUmask = frozenset()
        self.FileXattrs = frozenset()
        self.ProcEXE = frozenset()
        self.ProcArgv = frozenset()
        self.ProcEnvp = frozenset()
        self.ProcCwd = frozenset()
        self.ProcParent = frozenset()
        self.UserGroups = frozenset()
        self.PathToRoot = frozenset()
        self.UserCaps = frozenset()
        self.ProcLabel = frozenset()
        self.FileLabel = frozenset()
        self.SmackRules = frozenset()
        self.FileExecLabel = frozenset()
        self.TransmuteFolders = frozenset()
