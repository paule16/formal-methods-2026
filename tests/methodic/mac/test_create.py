from stat import ST_GID
from os import O_CREAT
from pytest import FixtureRequest, fixture

from tests.spec import LinuxTestSpec



@fixture(params=[False, True], ids=["setgidY", "setgidN"])
def setgid(request: FixtureRequest):
    return request.param


@fixture
def parent_mode(parent_write: bool, parent_execute: bool, setgid: bool):
    mode = 0o444
    if parent_write:
        mode |= 0o222
    if parent_execute:
        mode |= 0o111
    if setgid:
        mode |= ST_GID
    return mode


def test_open(
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
    t.add_setup("sudo echo \"label_one label_two rwx\" > /sys/fs/smackfs/load")
    t.make_dir(path="/sub_parent", owner=obj_user, group=obj_user, mode=sub_parent_mode)
    t.add_setup(f"sudo setfattr -n security.smack -v \"{obj_label}\" /sub_parent")
    t.make_dir(path="/sub_parent/parent", owner=obj_user, group=obj_user, mode=parent_mode)
    t.add_setup(f"sudo setfattr -n security.smack -v \"{obj_label}\" /sub_parent/parent")
    with t.make_program_and_run(
        user=caller_user,
        group=caller_user,
        umask=0o000,
        before_run=f"sudo setfattr -n security.smack -v \"{proc_label}\" /tst_prog",
    ) as prog:
        prog.seteuid(...)  # TODO: make this call
        prog.open("/sub_parent/parent/file", flags=O_CREAT, mode=0o777)


def test_creat(
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
    t.add_setup("sudo echo \"label_one label_two rwx\" > /sys/fs/smackfs/load")
    t.make_dir(path="/sub_parent", owner=obj_user, group=obj_user, mode=sub_parent_mode)
    t.add_setup(f"sudo setfattr -n security.smack -v \"{obj_label}\" /sub_parent")
    t.make_dir(path="/sub_parent/parent", owner=obj_user, group=obj_user, mode=parent_mode)
    t.add_setup(f"sudo setfattr -n security.smack -v \"{obj_label}\" /sub_parent/parent")
    with t.make_program_and_run(
        user=caller_user,
        group=caller_user,
        umask=0o000,
        before_run=f"sudo setfattr -n security.smack -v \"{proc_label}\" /tst_prog",
    ) as prog:
        prog.seteuid(...)  # TODO: make this call
        prog.creat("/sub_parent/parent/file", mode=0o777)


def test_link(
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
    t.add_setup("sudo echo \"label_one label_two rwx\" > /sys/fs/smackfs/load")
    t.make_dir(path="/sub_parent", owner=obj_user, group=obj_user, mode=sub_parent_mode)
    t.add_setup(f"sudo setfattr -n security.smack -v \"{obj_label}\" /sub_parent")
    t.make_dir(path="/sub_parent/parent", owner=obj_user, group=obj_user, mode=parent_mode)
    t.add_setup(f"sudo setfattr -n security.smack -v \"{obj_label}\" /sub_parent/parent")
    with t.make_program_and_run(
        user=caller_user,
        group=caller_user,
        umask=0o000,
        before_run=f"sudo setfattr -n security.smack -v \"{proc_label}\" /tst_prog",
    ) as prog:
        prog.seteuid(...)  # TODO: make this call
        prog.link("/parent/old_file", "/parent/new_file")


def test_mkdir(
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
    t.add_setup("sudo echo \"label_one label_two rwx\" > /sys/fs/smackfs/load")
    t.make_dir(path="/sub_parent", owner=obj_user, group=obj_user, mode=sub_parent_mode)
    t.add_setup(f"sudo setfattr -n security.smack -v \"{obj_label}\" /sub_parent")
    t.make_dir(path="/sub_parent/parent", owner=obj_user, group=obj_user, mode=parent_mode)
    t.add_setup(f"sudo setfattr -n security.smack -v \"{obj_label}\" /sub_parent/parent")
    with t.make_program_and_run(
        user=caller_user,
        group=caller_user,
        umask=0o000,
        before_run=f"sudo setfattr -n security.smack -v \"{proc_label}\" /tst_prog",
    ) as prog:
        prog.seteuid(...)  # TODO: make this call
        prog.mkdir("/sub_parent/parent/folder", mode=0o777)
