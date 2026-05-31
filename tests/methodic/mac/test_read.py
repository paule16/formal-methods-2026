from os import O_RDONLY

from tests.spec import LinuxTestSpec


def test_open_file(
    t: LinuxTestSpec,
    caller_user: str,
    proc_label: str,
    obj_label: str,
):
    obj_user = "obj_user"
    t.make_user(obj_user)
    if caller_user != "root":
        t.make_user(caller_user)
    t.make_dir(path="/parent", owner=obj_user, group=obj_user, mode=0o777)
    t.add_setup(f'sudo setfattr -n security.smack -v "{obj_label}" /parent')
    t.make_file("/parent/file", owner=obj_user, group=obj_user, mode=O_RDONLY)
    t.add_setup(f'sudo setfattr -n security.smack -v "{obj_label}" /parent/file')
    with t.make_program_and_run(
        user=caller_user,
        group=caller_user,
        umask=0o000,
        before_run=f'sudo setfattr -n security.smack -v "{proc_label}" /tst_prog',
    ) as prog:
        prog.seteuid(...)  # TODO: make this call
        prog.open("/parent/file", flags=O_RDONLY, mode=0o777)


def test_open_dir(
    t: LinuxTestSpec,
    caller_user: str,
    proc_label: str,
    obj_label: str,
):
    obj_user = "obj_user"
    t.make_user(obj_user)
    if caller_user != "root":
        t.make_user(caller_user)
    t.make_dir(path="/parent", owner=obj_user, group=obj_user, mode=0o777)
    t.add_setup(f'sudo setfattr -n security.smack -v "{obj_label}" /parent')
    t.make_dir("/parent/dir", owner=obj_user, group=obj_user, mode=O_RDONLY)
    t.add_setup(f'sudo setfattr -n security.smack -v "{obj_label}" /parent/dir')
    with t.make_program_and_run(
        user=caller_user,
        group=caller_user,
        umask=0o000,
        before_run=f'sudo setfattr -n security.smack -v "{proc_label}" /tst_prog',
    ) as prog:
        prog.seteuid(...)  # TODO: make this call
        prog.open("/parent/dir", flags=O_RDONLY, mode=0o777)
