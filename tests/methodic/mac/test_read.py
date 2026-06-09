from os import O_CREAT, O_DIRECTORY, O_RDONLY, O_RDWR

from pytest import FixtureRequest, fixture

from tests.spec import LinuxTestSpec
from .conftest import smack_labels


@fixture(
    params=smack_labels,
    ids=[f"DirL_{label}" for label in smack_labels],
)
def dir_label(request: FixtureRequest):
    return request.param


@fixture(
    params=[False, True],
    ids=["RdF", "RdT"],
)
def file_read(request: FixtureRequest):
    return request.param

@fixture(
    params=[False, True],
    ids=["WrF", "WrT"],
)
def file_write(request: FixtureRequest):
    return request.param


@fixture
def file_mode(file_read, file_write):
    mode = 0o000
    if file_read:
        mode |= 0o444
    if file_write:
        mode |= 0o222
    return mode


file_mode2smack_label = {
    0o000: "NOTHING",
    0o111: "EXECONLY",
    0o222: "WRONLY",
    0o333: "WREXEC",
    0o444: "READONLY",
    0o555: "READEXEC",
    0o666: "RDWR",
    0o777: "ALL",
}

file_mode_int2file_mode_str = {
    0o000: "nothing",
    0o111: "x",
    0o222: "w",
    0o333: "wx",
    0o444: "r",
    0o555: "rx",
    0o666: "rw",
    0o777: "rwx",
}


def test_reg_dir(
    t: LinuxTestSpec,
    proc_label: str,
    dir_label: str,
):
    obj_user = "obj_user"
    t.make_user(obj_user)
    caller_user = "caller_user"
    t.make_user(caller_user)
    t.make_rule(proc_label, "ROOT_LABEL", "rx")
    t.make_dir(
        "/parent", owner=obj_user, group=obj_user, mode=0o777, smack_label=dir_label
    )
    for file_type in ("file", "dir"):
        method = getattr(t, f"make_{file_type}")
        method(
            f"/parent/{file_type}",
            owner=obj_user,
            group=obj_user,
            mode=0o777,
            smack_label=dir_label,
        )
    with t.make_program_and_run(
        user=caller_user,
        group=caller_user,
        proc_label=proc_label,
        umask=0o000,
    ) as prog:
        for file_type in ("file", "dir"):
            prog.open(f"/parent/{file_type}", flags=O_RDONLY, mode=0o777)


def test_multi_dir(
    t: LinuxTestSpec,
    proc_label: str,
):
    obj_user = "obj_user"
    t.make_user(obj_user)
    caller_user = "caller_user"
    t.make_user(caller_user)
    t.make_rule(proc_label, "ROOT_LABEL", "rx")
    t.make_dir(
        path="/parent",
        owner=obj_user,
        group=obj_user,
        mode=0o777,
        smack_label=proc_label,
    )
    for file_type in ("file", "dir"):
        method = getattr(t, f"make_{file_type}")
        for ind, label in enumerate(smack_labels):
            method(
                f"/parent/{file_type}{ind}",
                obj_user,
                obj_user,
                0o777,
                smack_label=label,
            )
    with t.make_program_and_run(
        user=caller_user,
        group=caller_user,
        proc_label=proc_label,
        umask=0o000,
    ) as prog:
        for file_type in ("file", "dir"):
            for ind, label in enumerate(smack_labels):
                prog.open(f"/parent/{file_type}{ind}", flags=O_RDONLY, mode=0o777)


def test_open_file(
    t: LinuxTestSpec,
    caller_user: str,
    effective_user: str,
    proc_label: str,
    file_mode: int,
):
    obj_user = "obj_user"
    t.make_user(obj_user)
    if caller_user != "root" or effective_user != "root":
        t.make_user("non_root")
    t.make_dir(
        "/dir_to_read",
        obj_user,
        obj_user,
        file_mode | 0o111,
        file_mode2smack_label[file_mode],
    )
    t.make_dir(
        "/dir_to_write",
        obj_user,
        obj_user,
        file_mode | 0o111,
        file_mode2smack_label[file_mode],
    )
    t.make_file(
        "/file_to_read",
        obj_user,
        obj_user,
        file_mode,
        file_mode2smack_label[file_mode],
    )
    t.make_file(
        "/file_to_write",
        obj_user,
        obj_user,
        file_mode,
        file_mode2smack_label[file_mode],
    )
    t.make_rule(proc_label, "ROOT_LABEL", "rx")
    if file_mode_int2file_mode_str[file_mode] != file_mode_int2file_mode_str[0o000]:
        t.make_rule(proc_label, file_mode2smack_label[file_mode | 0o111], file_mode_int2file_mode_str[file_mode | 0o111])
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
        prog.open("/dir_to_read", O_RDONLY, file_mode)
        prog.open("/dir_to_write", O_RDWR, file_mode)
        prog.open("/file_to_read", O_RDONLY, file_mode)
        prog.open("/file_to_write", O_RDWR, file_mode)


def test_openat_file(
    t: LinuxTestSpec,
    caller_user: str,
    effective_user: str,
    proc_label: str,
    parent_execute: bool,
    file_mode: int,
):
    obj_user = "obj_user"
    t.make_user(obj_user)
    if caller_user != "root" or effective_user != "root":
        t.make_user("non_root")
    t.make_dir(
        "/sub_parent",
        obj_user,
        obj_user,
        0o777,
        smack_label="*",
    )
    t.make_dir(
        "/sub_parent/parent",
        obj_user,
        obj_user,
        0o777 if parent_execute else 0o666,
        smack_label="*" if parent_execute else "bad_label",
    )
    t.make_dir(
        "/sub_parent/parent/dir_to_read",
        obj_user,
        obj_user,
        file_mode | 0o111,
        file_mode2smack_label[file_mode],
    )
    t.make_dir(
        "/sub_parent/parent/dir_to_write",
        obj_user,
        obj_user,
        file_mode | 0o111,
        file_mode2smack_label[file_mode],
    )
    t.make_file(
        "/sub_parent/parent/file_to_read",
        obj_user,
        obj_user,
        file_mode,
        file_mode2smack_label[file_mode],
    )
    t.make_file(
        "/sub_parent/parent/file_to_write",
        obj_user,
        obj_user,
        file_mode,
        file_mode2smack_label[file_mode],
    )
    t.make_rule(proc_label, "ROOT_LABEL", "rx")
    if file_mode_int2file_mode_str[file_mode] != file_mode_int2file_mode_str[0o000]:
        t.make_rule(proc_label, file_mode2smack_label[file_mode | 0o111], file_mode_int2file_mode_str[file_mode | 0o111])
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

        prog.open_openat_close(
            "/sub_parent", O_DIRECTORY, 0,
            "parent/dir_to_read", O_RDONLY, file_mode,
        )
        prog.open_openat_close(
            "/sub_parent", O_DIRECTORY, 0,
            "parent/dir_to_write", O_RDWR, file_mode,
        )
        prog.open_openat_close(
            "/sub_parent", O_DIRECTORY, 0,
            "parent/file_to_read", O_RDONLY, file_mode,
        )
        prog.open_openat_close(
            "/sub_parent", O_DIRECTORY, 0,
            "parent/file_to_write", O_RDWR, file_mode,
        )
