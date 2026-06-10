from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
import io
import json
from os.path import basename, isabs
from pathlib import Path
from shutil import copytree
import subprocess
import sys
import tempfile
import textwrap
from typing import Any, Iterator, Optional

from anis.stages.trace_checkers import ModelTraceInterpreter
from anis.stages.systrace import TraceOperation
from anis.stages.monitor import make_call

from testing.dump import (
    LineStream,
    model_trace_py_saving,
    trace_py_saving,
    trace_txt_saving,
)
from testing.kernel_program_maker import KernelProgramMaker, MonitoredExeFile
from mediator.translator import TraceTranslator
from tests.spec import LinuxTestSpec, ProgramMakerTextProducer, TextProducer
from testing.initialiser import Snapshot, SnapshotBuilder

from anis.stages.invariants import check_axioms


class LinuxTestSpecImpl(LinuxTestSpec):
    def __init__(self, nodeid: str, m: Any, testpath: Path):
        super().__init__()
        self._nodeid = nodeid
        self._testpath = testpath
        self._setup_commands = list[str]()
        self._initialiser = SnapshotBuilder()
        self._additional_files = dict[str, str]()
        self._machine = m
        self._label = sha256(nodeid.encode()).hexdigest()[:10]

    def make_user(
        self, user: str, supplementary_groups: None | list[str] = None
    ) -> None:
        self._initialiser.add_user(user)
        if not supplementary_groups:
            self.add_setup(f"useradd {user}")
        else:
            self.add_setup(f"useradd -G {','.join(supplementary_groups)} {user}")

    def make_group(self, group: str) -> None:
        self._initialiser.add_group(group)
        self.add_setup(f"groupadd {group}")

    def make_file(
        self,
        path: str,
        owner: str,
        group: str,
        mode: int,
        smack_label: Optional[str] = None,
    ) -> None:
        if not isabs(path):
            raise ValueError("Relative paths are not supported")
        self._initialiser.add_file(path, smack_label)
        self.add_setup(f"touch {path}")
        self.add_setup(f"chown {owner}:{group} {path}")
        self.add_setup(f"chmod {mode:0o} {path}")
        if smack_label is not None:
            self.add_setup(f'setfattr -n security.SMACK64 -v "{smack_label}" {path}')

    def make_dir(
        self,
        path: str,
        owner: str,
        group: str,
        mode: int,
        smack_label: Optional[str] = None,
        transmute: bool = False
    ) -> None:
        if not isabs(path):
            raise ValueError("Relative paths are not supported")
        self._initialiser.add_dir(path, smack_label)
        self.add_setup(f"mkdir {path}")
        self.add_setup(f"chown {owner}:{group} {path}")
        self.add_setup(f"chmod {mode:0o} {path}")
        if smack_label is not None:
            self.add_setup(f'setfattr -n security.SMACK64 -v "{smack_label}" {path}')
        if transmute:
            self.add_setup(f'setfattr -n security.SMACK64TRANSMUTE -v "TRUE" {path}')

    def make_link(
        self,
        oldpath: str,
        newpath: str,
    ):
        if not isabs(oldpath) or not isabs(newpath):
            raise ValueError("Relative paths are not supported")
        self._initialiser.add_file(newpath, smack_label=None)
        self.add_setup(f"ln {oldpath} {newpath}")

    def make_rule(self, label1: str, label2: str, modes: str) -> None:
        self.add_setup(f'echo "{label1} {label2} {modes}" >> /sys/fs/smackfs/load2')
        self._initialiser.add_smack_rule(label1, label2, modes)

    def add_setup(self, setup_cmd: str) -> Any:
        self._setup_commands.append(setup_cmd)

    @contextmanager
    def make_program(self) -> Iterator[ProgramMakerTextProducer]:
        yield KernelProgramMaker()

    def compile(
        self,
        program_maker: TextProducer,
        path: str,
        make_file: bool = True,
        file_label: Optional[str] = None,
        proc_label: str = "",
        setuid_flag: bool = False,
    ) -> MonitoredExeFile:
        source_path = f"{path}.c"
        if basename(source_path) in self._additional_files:
            raise ValueError("Additional file redefined")

        program_text = program_maker.get_text()
        self._additional_files[basename(source_path)] = program_text
        if make_file:
            self.make_file(path, "root", "root", 0o777, smack_label=file_label)
        self.add_setup(f"gcc -static -o {path} /progs/{basename(source_path)}")
        if setuid_flag:
            self.add_setup(f"chmod u+s {path}")
        if not proc_label:
            proc_label = "^"
        self.add_setup(
            f'sudo setfattr -n security.SMACK64EXEC -v "{proc_label}" {path}'
        )
        return MonitoredExeFile(path)

    @contextmanager
    def make_program_and_run(
        self,
        user: str,
        group: str,
        umask: int,
        runner: str = "<>",
        make_file: bool = True,
        before_run: str | None = None,
        after_run: str | None = None,
        additional_runner_cmd: str = "",
        proc_label: str = "",
        setuid_flag: bool = False,
    ):
        with self.make_program() as prog:
            yield prog
        exeFile = self.compile(
            prog, "/tst_prog", make_file, None, proc_label, setuid_flag
        )
        self.run(
            exeFile,
            user,
            group,
            umask,
            runner,
            before_run,
            after_run,
            additional_runner_cmd=additional_runner_cmd,
        )

    def run(
        self,
        exeFile: MonitoredExeFile,
        user: str,
        group: str,
        umask: int,
        runner: str,
        before_run: str | None,
        after_run: str | None,
        additional_runner_cmd: str = "",
    ):
        with self._run_without_preparing_image(
            exeFile=exeFile,
            user=user,
            group=group,
            umask=umask,
            runner=runner,
            before_run=before_run,
            after_run=after_run,
            additional_runner_cmd=additional_runner_cmd,
        ) as trace:
            self._check(trace)

    @contextmanager
    def _run_without_preparing_image(
        self,
        exeFile: MonitoredExeFile,
        user: str,
        group: str,
        umask: int,
        runner: str,
        before_run: str | None,
        after_run: str | None,
        additional_runner_cmd: str | None = None,
    ):

        container_name = f"anis_{self._label}"

        with tempfile.TemporaryDirectory() as base:
            base_path = Path(base)
            for path, contents in self._additional_files.items():
                (base_path / basename(path)).write_text(contents)

            gatherinfo_commands = (
                self._initialiser.make_text_of_gatherinfo_file()
            )  # this make important
            if additional_runner_cmd:
                additional_runner_cmd += ";"
            runner_cmd = runner.replace(
                "<>",
                f'(chfn --other="umask={umask:0o}" {user}; {additional_runner_cmd} /monitor/monitor run sudo -HE -u {user} -g {group} {exeFile.path})',
            )

            if not before_run:
                # 1. run setup
                # 2. run gather_info with printing output
                # 3. run runner

                cmd = " && ".join(
                    self._setup_smack()
                    + self._setup_commands
                    + gatherinfo_commands
                    + [runner_cmd]
                )

                cmd = f"flock /tmp/tests.lock -c '{cmd}'"

                proc = None
                try:
                    print("run...", file=sys.stderr, end=" ")
                    proc = subprocess.run(
                        [
                            "sudo",
                            "podman",
                            "run",
                            "--rm",
                            "--privileged",
                            "-i",
                            f"--name={container_name}",
                            # "--cap-add=CAP_BPF",
                            # "--cap-add=CAP_SYS_ADMIN",
                            "-v",
                            f"{base_path}:/progs:ro",
                            "-v",
                            "/sys/fs/bpf:/sys/fs/bpf:rw",
                            "-v",
                            "/sys/kernel:/sys/kernel:ro",
                            "-v",
                            "./monitor:/monitor:ro",
                            "-v",
                            "/tmp:/tmp:rw",
                            # '--pid=host',
                            # '--network=host',
                            # '--security-opt', 'label=disable',
                            "anis:base",
                            "/bin/bash",
                        ],
                        input=cmd,
                        encoding="utf-8",
                        check=True,
                        capture_output=True,
                    )
                    if proc.stderr:
                        raise ValueError(proc.stderr)
                    print("ok", file=sys.stderr)

                    with open("/tmp/" + container_name, "w") as f:
                        print(proc.stdout, file=f)

                    yield io.StringIO(proc.stdout)
                    # yield self._PrependedStream(info, proc.stdout)

                except Exception as e:
                    # subprocess.run(['sudo', 'podman', 'stop', container_name])
                    subprocess.run(["sudo", "podman", "rm", "-f", container_name])
                    raise

            else:
                subprocess.run(
                    [
                        "sudo",
                        "podman",
                        "run",
                        "-d",
                        "--privileged",
                        "-i",
                        f"--name={container_name}",
                        # "--cap-add=CAP_BPF",
                        # "--cap-add=CAP_SYS_ADMIN",
                        "-v",
                        f"{base_path}:/progs:ro",
                        "-v",
                        "/sys/fs/bpf:/sys/fs/bpf:rw",
                        "-v",
                        "/sys/kernel:/sys/kernel:ro",
                        "-v",
                        "./monitor:/monitor:ro",
                        # '--pid=host',
                        # '--network=host',
                        # '--security-opt', 'label=disable',
                        "anis:base",
                        "/bin/bash",
                    ],
                    check=True,
                    stdout=subprocess.DEVNULL,
                )

                try:
                    # 1. run setup
                    # 2. run gather_info with printing output
                    cmd = " && ".join(
                        self._setup_smack() + self._setup_commands + gatherinfo_commands
                    )
                    print("setup...", file=sys.stderr, end=" ")
                    proc = subprocess.run(
                        [
                            "sudo",
                            "podman",
                            "exec",
                            "-i",
                            container_name,
                            "/bin/bash",
                        ],
                        input=cmd,
                        encoding="utf-8",
                        check=True,
                        capture_output=True,
                    )
                    if proc.stderr:
                        raise ValueError(proc.stderr)
                    info = proc.stdout
                    print("ok", file=sys.stderr)

                    # 3. run before_run
                    if before_run:
                        subprocess.run(
                            ["sudo", "/bin/bash"],
                            input=before_run,
                            encoding="utf-8",
                            check=True,
                        )

                except:
                    # subprocess.run(['sudo', 'podman', 'stop', container_name])
                    subprocess.run(["sudo", "podman", "rm", "-f", container_name])
                    raise

                # 4. run runner
                proc = None
                try:
                    print("run...", file=sys.stderr, end=" ")
                    proc = subprocess.run(
                        [
                            "sudo",
                            "podman",
                            "exec",
                            "-i",
                            container_name,
                            "/bin/bash",
                        ],
                        input=runner_cmd,
                        encoding="utf-8",
                        capture_output=True,
                    )
                    print("ok", file=sys.stderr)

                    if proc.stderr:
                        raise ValueError(proc.stderr)
                    if not proc.stdout:
                        raise ValueError("No stdout")

                    yield io.StringIO(info + proc.stdout)
                except:
                    subprocess.run(["sudo", "podman", "kill", container_name])
                    raise
                finally:
                    if proc:
                        # if proc.stdout:
                        #     proc.stdout.close()
                        print("end...", file=sys.stderr, end=" ")
                        subprocess.run(
                            ["sudo", "podman", "attach", "--no-stdin", container_name],
                            stdout=subprocess.DEVNULL,
                        )
                        subprocess.run(
                            ["sudo", "podman", "rm", "-f", container_name],
                            stdout=subprocess.DEVNULL,
                        )
                        print("ok", file=sys.stderr)
                        # proc.wait(timeout=5)

                    # 5. run after_run
                    if after_run:
                        subprocess.run(
                            ["sudo", "/bin/bash"], input=after_run, encoding="utf-8"
                        )

    def _setup_smack(self) -> list[str]:
        return [
            "mount -t smackfs smackfs /sys/fs/smackfs",  # enable smack
            'setfattr -n "security.SMACK64" -v "ROOT_LABEL" /',  # set ROOT_Label on root-folder
        ]

    def _check(self, raw_trace: LineStream):

        with (
            trace_txt_saving(self._label, raw_trace) as trace,
            trace_py_saving(self._label, TraceTranslator) as TT,
            model_trace_py_saving(self._label, ModelTraceInterpreter) as MT,
        ):
            # print(raw_trace.read())
            # raise Exception
            snapshot = self._initialiser.read_gathered_info(trace)

            tt = TT(
                model_trace=MT(self._machine),
                m=self._machine,
                root_dev=snapshot.root.dev,
                root_ino=snapshot.root.ino,
                root_uid=snapshot.root.uid,
                root_gid=snapshot.root.gid,
            )

            # print("Trace:")
            # for _ in range(100):
            #     try:
            #         print(trace.readline())
            #     except:
            #         print("Ended printing!")
            #         break

            self._replay_setup(snapshot, tt)
            self._replay_login(trace, tt)
            self._replay_trace(trace, tt)

    def _replay_setup(self, snapshot: Snapshot, tt: TraceTranslator):

        for group in snapshot.groups:
            tt.add_init_group(gid=group.gid)

        for user in snapshot.users:
            tt.add_init_user(
                uid=user.uid, primary_gid=user.gid, supplementary_gids=user.gids
            )

        for path, s in snapshot.folders.items():
            tt.add_init_folder(
                path=path, dev=s.dev, ino=s.ino, uid=s.uid, gid=s.gid, perms=s.perms
            )

        for attrs in snapshot.folders_xattrs:
            tt.set_xattrs_init_file(path=attrs.path, xattrs=attrs.xattrs)

        for path, s in snapshot.files.items():
            tt.add_init_file_or_link(
                path=path, dev=s.dev, ino=s.ino, uid=s.uid, gid=s.gid, perms=s.perms
            )

        for attrs in snapshot.files_xattrs:
            tt.set_xattrs_init_file(path=attrs.path, xattrs=attrs.xattrs)

        tt.set_init_acl(data=snapshot.acl)

        # Smack
        for path, file_smack_label in snapshot.file_smack_labels:
            tt.set_file_label(path, 0, file_smack_label, 0)

        for path, file_exec_smack_label in snapshot.file_exec_smack_labels:
            tt.set_file_exec_label(path, 0, file_exec_smack_label, 0)

        for path, dir_transmute in snapshot.dirs_transmute:
            tt.set_directory_transmute(path, 0, 0)

        for label1, label2, modes in snapshot.smack_rules:
            tt.add_smack_rule(label1, label2, modes)

        check_axioms(self._machine)

    def _replay_login(self, trace: LineStream, tt: TraceTranslator):

        line = trace.readline()
        if not line:
            raise ValueError("EOF")
        login = json.loads(line)
        if login["syscall"] != "execve":
            raise ValueError("No login execve in the trace")
        if login["ret"] != 0:
            raise ValueError("Failed login in the trace")

        tt.login(
            uid=login["euid"],
            gid=login["egid"],
            pid=login["pid"],
            exeFile=login["pathname"],
            umask=login["umask"],
            smack_label=login["smack_subj"],
        )

    def _replay_trace(self, trace: LineStream, tt: TraceTranslator):

        for ind, line in enumerate(trace):
            print(f"{ind = }")
            print(line)
            event = json.loads(line)
            self.clean_event(event)
            t_operation = TraceOperation(
                name=event["syscall"], ret=event["ret"], args=event
            )
            operation = make_call(t_operation)
            getattr(tt, operation.name)(**operation.args)
            check_axioms(self._machine)

    def clean_event(self, event):
        for key in (
            "smack_mmap",
            "smack_flags",
            "smack_flags_hex",
            "smack_flags_names",
        ):
            del event[key]
        for key, subst_key in (("smack_obj", "smack_label"),):
            event[subst_key] = event[key]
            del event[key]
