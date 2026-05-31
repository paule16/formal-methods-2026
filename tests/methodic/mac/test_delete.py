from stat import S_ISVTX
from os import O_CREAT
from pytest import fixture, FixtureRequest

from tests.spec import LinuxTestSpec


@fixture(params=[False, True], ids=["stickyY", "stickyN"])
def set_sticky_bit(request: FixtureRequest):
    return request.param


@fixture
def parent_mode(parent_write: bool, parent_execute: bool, set_sticky_bit: bool):
    mode = 0o444
    if parent_write:
        mode |= 0o222
    if parent_execute:
        mode |= 0o111
    if set_sticky_bit:
        mode |= S_ISVTX
    return mode


def test_unlink_file(
    t: LinuxTestSpec,
    caller_user: str,
    proc_label: str,
    obj_label: str,
    parent_mode: int,
    sub_parent_mode: int,
):
    obj_user = "obj_user"
    t.make_user(obj_user)
    if caller_user != "root":
        t.make_user(caller_user)
    t.add_setup('sudo echo "label_one label_two rwx" > /sys/fs/smackfs/load')
    t.make_dir(path="/sub_parent", owner=obj_user, group=obj_user, mode=sub_parent_mode)
    t.add_setup(f'sudo setfattr -n security.smack -v "{obj_label}" /sub_parent')
    t.make_dir(
        path="/sub_parent/parent", owner=obj_user, group=obj_user, mode=parent_mode
    )
    t.add_setup(f'sudo setfattr -n security.smack -v "{obj_label}" /sub_parent/parent')
    t.make_file("/sub_parent/parent/file", owner=obj_user, group=obj_user, mode=0o777)
    with t.make_program_and_run(
        user=caller_user,
        group=caller_user,
        umask=0o000,
        before_run=f'sudo setfattr -n security.smack -v "{proc_label}" /tst_prog',
    ) as prog:
        prog.seteuid(...)  # TODO: make this call
        prog.unlink("/sub_parent/parent/file")


def test_unlink_link(
    t: LinuxTestSpec,
    caller_user: str,
    proc_label: str,
    obj_label: str,
    parent_mode: int,
    sub_parent_mode: int,
):
    obj_user = "obj_user"
    t.make_user(obj_user)
    if caller_user != "root":
        t.make_user(caller_user)
    t.add_setup('sudo echo "label_one label_two rwx" > /sys/fs/smackfs/load')
    t.make_dir(path="/sub_parent", owner=obj_user, group=obj_user, mode=sub_parent_mode)
    t.add_setup(f'sudo setfattr -n security.smack -v "{obj_label}" /sub_parent')
    t.make_dir(
        path="/sub_parent/parent", owner=obj_user, group=obj_user, mode=parent_mode
    )
    t.add_setup(f'sudo setfattr -n security.smack -v "{obj_label}" /sub_parent/parent')
    t.make_file("/sub_parent/parent/file", owner=obj_user, group=obj_user, mode=0o777)
    t.make_link(
        "/sub_parent/parent/file", "/sub_parent/parent/link"
    )  # TODO: no such method
    with t.make_program_and_run(
        user=caller_user,
        group=caller_user,
        umask=0o000,
        before_run=f'sudo setfattr -n security.smack -v "{proc_label}" /tst_prog',
    ) as prog:
        prog.seteuid(...)  # TODO: make this call
        prog.unlink("/sub_parent/parent/link")


def test_rmdir(
    t: LinuxTestSpec,
    caller_user: str,
    proc_label: str,
    obj_label: str,
    parent_mode: int,
    sub_parent_mode: int,
):
    obj_user = "obj_user"
    t.make_user(obj_user)
    if caller_user != "root":
        t.make_user(caller_user)
    t.add_setup('sudo echo "label_one label_two rwx" > /sys/fs/smackfs/load')
    t.make_dir(path="/sub_parent", owner=obj_user, group=obj_user, mode=sub_parent_mode)
    t.add_setup(f'sudo setfattr -n security.smack -v "{obj_label}" /sub_parent')
    t.make_dir(
        path="/sub_parent/parent", owner=obj_user, group=obj_user, mode=parent_mode
    )
    t.add_setup(f'sudo setfattr -n security.smack -v "{obj_label}" /sub_parent/parent')
    t.make_dir("/sub_parent/parent/folder", owner=obj_user, group=obj_user, mode=0o777)
    with t.make_program_and_run(
        user=caller_user,
        group=caller_user,
        umask=0o000,
        before_run=f'sudo setfattr -n security.smack -v "{proc_label}" /tst_prog',
    ) as prog:
        prog.seteuid(...)  # TODO: make this call
        prog.rmdir("/parent/folder", mode=0o777)
