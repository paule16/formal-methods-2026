from os import O_CREAT, O_DIRECTORY, O_EXCL, O_RDONLY

from pytest import FixtureRequest, fixture

from tests.spec import LinuxTestSpec


@fixture(params=[False, True], ids=["with_rule", "without_rule"])
def set_rule(request: FixtureRequest):
    return request.param


def test_transmute(
    t: LinuxTestSpec,
    set_rule: bool
):
    proc_label = "proc"
    dir_label = "dir"
    t.make_user("user")
    t.make_dir(
        path="/dir",
        owner="user",
        group="user",
        mode=0o777,
        smack_label=dir_label,
        transmute=True,
    )

    if set_rule:
        t.make_rule(proc_label, dir_label, "rwt")

    with t.make_program_and_run(
        user="user",
        group="user",
        umask=0o000,
        proc_label=proc_label,
        setuid_flag=True,
    ) as prog:
        prog.creat(
            pathname="/dir/file1",
            mode=0o777,
            fatal=True,
        )
        prog.open(
            pathname="/dir/file2",
            flags=O_CREAT | O_EXCL,
            mode=0o777,
            fatal=True,
        )
        fd = prog.open(
            pathname="/dir",
            flags=O_DIRECTORY | O_RDONLY,
            mode=0o777,
            fatal=True,
        )
        prog.openat(
            dirfd=fd,
            pathname="file3",
            flags=O_CREAT | O_EXCL,
            mode=0o777,
            fatal=True,
        )
        prog.mkdir(
            pathname="/dir/dir1",
            mode=0o777,
            fatal=True,
        )

