from stat import S_ISVTX
from os import O_CREAT
from pytest import fixture, FixtureRequest

from tests.spec import LinuxTestSpec


@fixture(params=[False, True], ids=["stickyF", "stickyT"])
def set_sticky_bit(request: FixtureRequest):
    return request.param


@fixture(
    params=[(False, False), (False, True), (True, False), (True, True)],
    ids=["Parent_WrF_ExF", "Parent_WrF_ExT", "Parent_WrT_ExF", "Parent_WrT_ExT"],
)
def parent_mode(request: FixtureRequest, set_sticky_bit: bool) -> tuple[int, str]:
    parent_write, parent_execute = request.param
    label = "bad_label"
    mode = 0o444  # Full read
    if parent_execute:
        mode |= 0o111
        label = "_"
    if parent_write:
        mode |= 0o222
        label = "*"
    if set_sticky_bit:
        mode |= S_ISVTX
    return mode, label


@fixture(
    params=[False, True],
    ids=["SubParent_ExF", "SubParent_ExT"],
)
def sub_parent_mode(request: FixtureRequest) -> tuple[int, str]:
    if request.param:
        return 0o777, "*"
    return 0o666, "bad_label"  # At least rw


def test_rmdir(
    t: LinuxTestSpec,
    caller_user: str,
    effective_user: str,
    proc_label: str,
    parent_mode: tuple[int, str],
    sub_parent_mode: tuple[int, str],
):
    obj_user = "obj_user"
    t.make_user(obj_user)
    if caller_user != "root" or effective_user != "root":
        t.make_user("non_root")
    t.make_rule(proc_label, "ROOT_LABEL", "rx")
    t.make_dir(
        path="/sub_parent",
        owner=obj_user,
        group=obj_user,
        mode=sub_parent_mode[0],
        smack_label=sub_parent_mode[1],
    )
    t.make_dir(
        path="/sub_parent/parent",
        owner=obj_user,
        group=obj_user,
        mode=parent_mode[0],
        smack_label=parent_mode[1],
    )
    t.make_file(
        path="/sub_parent/parent/file_to_link",
        owner=obj_user,
        group=obj_user,
        mode=0o777,
        smack_label="*",
    )
    t.make_file(
        path="/sub_parent/parent/file_to_unlink",
        owner=obj_user,
        group=obj_user,
        mode=0o777,
        smack_label="*",
    )
    t.make_link("/sub_parent/parent/file_to_link", "/sub_parent/parent/link_to_unlink")
    t.make_dir(
        path="/sub_parent/parent/dir_to_remove",
        owner=obj_user,
        group=obj_user,
        mode=parent_mode[0],
        smack_label=parent_mode[1],
    )
    with t.make_program_and_run(
        user=caller_user,
        group=caller_user,
        umask=0o000,
        proc_label=proc_label,
        setuid_flag=True,
    ) as prog:
        if effective_user == "root":
            prog.seteuid(0, fatal=True)
        else:
            prog.seteuid(1001, fatal=True)
        prog.unlink("/sub_parent/parent/file_to_unlink")
        prog.unlink("/sub_parent/parent/link_to_unlink")
        prog.rmdir("/sub_parent/parent/dir_to_remove")
