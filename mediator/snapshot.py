from dataclasses import dataclass


@dataclass
class Snapshot:
    init_users: dict[str, tuple[int, int, list[int]]] # username |-> (uid, primary group gid, supplementary groups gids)
    init_groups: list[int] # gids
    init_files: dict[str, tuple[int, int, int, int, int, dict[str, str], list[str]]] # path |-> (stat, xattrs, acls) 
    init_dirs: dict[str, tuple[int, int, int, int, int, dict[str, str], list[str]]]
    root_dev: int
    root_ino: int
    root_uid: int
    root_gid: int

    uid: int
    gid: int
    umask: int
    exeFile_dev: int
    exeFile_ino: int
    pid: int