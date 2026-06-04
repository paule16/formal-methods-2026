from os import O_RDONLY

from pytest import FixtureRequest, fixture

from tests.spec import LinuxTestSpec
from .conftest import smack_labels


@fixture(
    params=smack_labels,
    ids=[f"DirL_{label}" for label in smack_labels],
)
def dir_label(request: FixtureRequest):
    return request.param


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
