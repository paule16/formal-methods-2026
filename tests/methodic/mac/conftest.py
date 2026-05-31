from pytest import FixtureRequest, fixture


users = ["root", "non_root"]
regular_smack_labels = ("label_one", "label_two")
special_smack_labels = ("*", "^", "_")
smack_labels = regular_smack_labels + special_smack_labels


@fixture(params=users)
def caller_user(request: FixtureRequest):
    return request.param


@fixture(params=users)
def effective_user(request: FixtureRequest):
    return request.param


@fixture(params=regular_smack_labels + ("^", "_"))  # Cannot set * as SMACK64EXEC
def proc_label(request: FixtureRequest):
    return request.param


@fixture(params=smack_labels)
def obj_label(request: FixtureRequest):
    return request.param


@fixture(params=[False, True], ids=["ExecF", "ExecT"])
def parent_execute(request: FixtureRequest):
    return request.param


@fixture(params=[False, True], ids=["WrF", "WrT"])
def parent_write(request: FixtureRequest):
    return request.param
