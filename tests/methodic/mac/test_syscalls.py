from pytest import FixtureRequest, fixture

from tests.spec import LinuxTestSpec


@fixture(
    params=[False, True],
    ids=["FileRdF", "FileRdT"],
)
def file_read(request: FixtureRequest):
    return request.param


@fixture(
    params=[False, True],
    ids=["FileWrF", "FileWrT"],
)
def file_write(request: FixtureRequest):
    return request.param


def test_ch_syscalls(
    t: LinuxTestSpec,
):
    obj_user = "obj_user"
    t.make_user(obj_user)
    new_obj_user = "new_obj_user"
    t.make_user(new_obj_user)
    t.make_dir(
        "/parent",
        obj_user,
        obj_user,
        0o777,
        smack_label="bad_label",
    )
    t.make_file(
        "/parent/file",
        obj_user,
        obj_user,
        0o777,
        smack_label="bad_label",
    )
    with t.make_program_and_run(
        obj_user,
        obj_user,
        0o000,
        proc_label="_",
        runner=f"export NEW_OBJ_USER=$(id -u {new_obj_user}); <>",
    ) as prog:
        new_obj_user_id = prog.bound_value_as_uid_t(prog.to_int(prog.xgetenv("NEW_OBJ_USER")))
        # All of them should fail
        prog.chmod("/parent/file", 0o000)
        prog.chown("/parent/file", new_obj_user_id, 1001)
        prog.chdir("/parent")


def test_execve(
    t: LinuxTestSpec,
    parent_execute: bool,
    file_read: bool,
):
    obj_user = "obj_user"
    t.make_user("obj_user")
    t.make_dir(
        "/parent",
        obj_user,
        obj_user,
        0o777,
        smack_label="_" if parent_execute else "bad_label",
    )
    with t.make_program() as empty_prog:
        empty_prog.exit(0)
    empty = t.compile(
        empty_prog,
        "/parent/tst_empty",
        file_label="_" if file_read else "bad_label",
    )

    with t.make_program_and_run(
        user=obj_user,
        group=obj_user,
        umask=0o000,
        proc_label="proc_label",
    ) as prog:
        args = prog.bound_value_as_charparray(init=["/tst_empty"], prefix="args")
        envp = prog.bound_value_as_charparray(init=[], prefix="envp")
        prog.execve(empty, args, envp)


def test_getxattr(
    t: LinuxTestSpec,
    parent_execute: bool,
    file_read: bool,
):
    obj_user = "obj_user"
    t.make_user(obj_user)
    t.make_dir(
        "/parent",
        obj_user,
        obj_user,
        0o777,
        smack_label="_" if parent_execute else "bad_label",
    )
    t.make_file(
        "/parent/file",
        obj_user,
        obj_user,
        0o777,
        smack_label="*" if file_read else "bad_label",
    )
    t.add_setup("setfattr -n user.test -v \"test\" /parent/file")
    with t.make_program_and_run(
        user=obj_user,
        group=obj_user,
        umask=0o000,
        proc_label="proc_label"
    ) as prog:
        buf = prog.bound_value_as_chararray(1024)
        prog.getxattr("/parent/file", "user.test", buf, 16)


def test_setxattr(
    t: LinuxTestSpec,
    parent_execute: bool,
    file_write: bool,
):
    obj_user = "obj_user"
    t.make_user(obj_user)
    t.make_dir(
        "/parent",
        obj_user,
        obj_user,
        0o777,
        smack_label="_" if parent_execute else "bad_label",
    )
    t.make_file(
        "/parent/file",
        obj_user,
        obj_user,
        0o777,
        smack_label="*" if file_write else "bad_label",
    )
    with t.make_program_and_run(
        user=obj_user,
        group=obj_user,
        umask=0o000,
        proc_label="proc_label",
    ) as prog:
        prog.setxattr("/parent/file", "user.test", b"test", len("test"), 0)
