#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only
#

import multiprocessing
from types import FrameType
from typing import Callable, Iterator, Optional, Tuple, List, Generator
import sys
import pathlib
import platform
import pwd
import random
import signal
import socket
import subprocess
import shlex
import shutil
import stat
import string
import os
import queue
import tempfile
from . import logger
import time
import threading
import contextlib

import bt2


class TemporaryDirectory:
    def __init__(self, prefix):
        # type: (str) -> None
        self._cleanup_callbacks = []
        self._directory_path = tempfile.mkdtemp(prefix=prefix)

    def __del__(self):
        try:
            for func, args, kwargs in self._cleanup_callbacks:
                func(*args, **kwargs)
        finally:
            if os.getenv("LTTNG_TEST_PRESERVE_TEST_ENV", "0") != "0":
                destination = os.getenv("LTTNG_TEST_PRESERVE_TEST_ENV_DIR", None)
                if destination is not None and pathlib.Path(destination).is_dir():
                    shutil.move(self._directory_path, destination)
            else:
                shutil.rmtree(self._directory_path, ignore_errors=True)

    def add_cleanup_callback(self, func, *args, **kwargs):
        self._cleanup_callbacks.append((func, args, kwargs))

    @property
    def path(self):
        # type: () -> pathlib.Path
        return pathlib.Path(self._directory_path)


class _SignalWaitQueue:
    """
    Utility class useful to wait for a signal before proceeding.

    Simply register the `signal` method as the handler for the signal you are
    interested in and call `wait_for_signal` to wait for its reception.

    Registering a signal:
        signal.signal(signal.SIGWHATEVER, queue.signal)

    Waiting for the signal:
        queue.wait_for_signal()
    """

    def __init__(self):
        self._queue = queue.Queue()  # type: queue.Queue

    def signal(
        self,
        signal_number,
        frame,  # type: Optional[FrameType]
    ):
        self._queue.put_nowait(signal_number)

    def wait_for_signal(self):
        # This uses a timeout + retry loop to avoid
        # issues with hanging on yocto kirkstone powerpc
        wait = True
        while wait:
            try:
                self._queue.get(block=True, timeout=1)
                wait = False
            except queue.Empty:
                continue
            except Exception as e:
                raise e

    @contextlib.contextmanager
    def intercept_signal(self, signal_number):
        # type: (int) -> Generator[None, None, None]
        original_handler = signal.getsignal(signal_number)
        signal.signal(signal_number, self.signal)
        try:
            yield
        except:
            # Restore the original signal handler and forward the exception.
            raise
        finally:
            signal.signal(signal_number, original_handler)


class _LiveViewer:
    """
    Create a babeltrace2 live viewer.
    """

    def __init__(
        self,
        environment,  # type: Environment
        session,  # type: str
        hostname=None,  # type: Optional[str]
    ):
        self._environment = environment
        self._session = session
        self._hostname = hostname
        if self._hostname is None:
            self._hostname = socket.gethostname()
        self._events = []

        ctf_live_cc = bt2.find_plugin("ctf").source_component_classes["lttng-live"]
        self._live_iterator = bt2.TraceCollectionMessageIterator(
            bt2.ComponentSpec(
                ctf_live_cc,
                {
                    "inputs": [
                        "net://localhost:{}/host/{}/{}".format(
                            environment.lttng_relayd_live_port,
                            self._hostname,
                            session,
                        )
                    ],
                    "session-not-found-action": "end",
                },
            )
        )

        try:
            # Cause the connection to be initiated since tests
            # tend to wait for a viewer to be connected before proceeding.
            msg = next(self._live_iterator)
            self._events.append(msg)
        except bt2.TryAgain:
            pass

    @property
    def output(self):
        return self._events

    @property
    def messages(self):
        return [x for x in self._events if type(x) is bt2._EventMessageConst]

    def _drain(self, retry=False, timeout=0):
        start = time.time()
        while True:
            try:
                for msg in self._live_iterator:
                    if type(msg) is bt2._MessageIteratorInactivityMessageConst:
                        break
                    self._events.append(msg)
                break
            except bt2.TryAgain as e:
                if retry:
                    if timeout > 0 and (time.time() - start) > timeout:
                        break
                    time.sleep(0.01)
                    continue
                else:
                    break

    def is_connected(self):
        ctf_live_cc = bt2.find_plugin("ctf").source_component_classes["lttng-live"]
        self._environment._log(
            "Checking for connected clients at 'net://localhost:{}'".format(
                self._environment.lttng_relayd_live_port
            )
        )
        query_executor = bt2.QueryExecutor(
            ctf_live_cc,
            "sessions",
            params={
                "url": "net://localhost:{}".format(
                    self._environment.lttng_relayd_live_port
                )
            },
        )

        for live_session in query_executor.query():
            if (
                live_session["session-name"] == self._session
                and live_session["client-count"] >= 1
            ):
                self._environment._log(
                    "Session '{}' has {} connected clients".format(
                        live_session["session-name"], live_session["client-count"]
                    )
                )
                return True
        return False

    def _wait_until(self, desired_state: bool, timeout=0):
        connected_state = not desired_state
        started = time.time()
        while connected_state != desired_state:
            try:
                if timeout != 0 and (time.time() - started) > timeout:
                    raise RuntimeError(
                        "Timed out waiting for connected clients on session '{}' after {}s".format(
                            self._session, time.time() - started
                        )
                    )

                connected_state = self.is_connected()
            except bt2._Error:
                time.sleep(0.01)
                continue
        return connected_state

    def wait_until_disconnected(self, timeout=0):
        return self._wait_until(False, timeout)

    def wait_until_connected(self, timeout=0):
        return self._wait_until(True, timeout)

    def wait(self, timeout=0, close_iterator=True):
        if self._live_iterator:
            self._drain(retry=True, timeout=timeout)
            if close_iterator:
                del self._live_iterator
                self._live_iterator = None

    def __del__(self):
        pass


class _WaitTraceTestApplication:
    """
    Create an application that waits before tracing. This allows a test to
    launch an application, get its PID, and get it to start tracing when it
    has completed its setup.
    """

    def __init__(
        self,
        binary_path,  # type: pathlib.Path
        event_count,  # type: int
        environment,  # type: Environment
        wait_time_between_events_us=0,  # type: int
        wait_before_exit=False,  # type: bool
        wait_before_exit_file_path=None,  # type: Optional[pathlib.Path]
        run_as=None,  # type: Optional[str]
        text_size=None,  # type: Optional[int]
        fill_text=False,  # type: bool
        wait_before_last_event=False,  # type: bool
        wait_before_last_event_file_path=None,  # type: Optional[pathlib.Path]
        extra_env_vars=dict(),
    ):
        self._process = None
        self._environment = environment  # type: Environment
        self._iteration_count = event_count
        # File that the application will wait to see before tracing its events.
        dir = (
            self._compat_pathlike(environment.lttng_home_location)
            if environment.lttng_home_location
            else None
        )
        if run_as is not None:
            dir = os.path.join(dir, run_as)
        self._app_start_tracing_file_path = pathlib.Path(
            tempfile.mktemp(
                prefix="app_",
                suffix="_start_tracing",
                dir=dir,
            )
        )

        # File that the application will create when all the last event has been emitted
        self._app_before_last_event_file_path = pathlib.Path(
            tempfile.mktemp(
                prefix="app_",
                suffix="_before_last_event",
                dir=dir,
            )
        )

        # File that the application will create when all events have been emitted.
        self._app_tracing_done_file_path = pathlib.Path(
            tempfile.mktemp(
                prefix="app_",
                suffix="_done_tracing",
                dir=dir,
            )
        )

        if wait_before_exit and wait_before_exit_file_path is None:
            wait_before_exit_file_path = pathlib.Path(
                tempfile.mktemp(
                    prefix="app_",
                    suffix="_exit",
                    dir=dir,
                )
            )

        self._wait_before_exit_file_path = wait_before_exit_file_path
        self._has_returned = False
        self._tracing_started = False
        if wait_before_last_event and wait_before_last_event_file_path is None:
            wait_before_last_event_file_path = pathlib.Path(
                tempfile.mktemp(prefix="app_", suffix="_last_event", dir=dir)
            )

        self._wait_before_last_event_file_path = wait_before_last_event_file_path
        test_app_env = os.environ.copy()
        if environment.lttng_home_location is not None:
            test_app_env["LTTNG_HOME"] = str(environment.lttng_home_location)
        if environment.lttng_rundir is not None:
            test_app_env["LTTNG_UST_APP_PATH"] = str(environment.lttng_rundir)

        # Make sure the app is blocked until it is properly registered to
        # the session daemon.
        test_app_env["LTTNG_UST_REGISTER_TIMEOUT"] = "-1"
        test_app_env.update(extra_env_vars)

        # File that the application will create to indicate it has completed its initialization.
        app_ready_file_path = tempfile.mktemp(
            prefix="app_",
            suffix="_ready",
            dir=dir,
        )  # type: str

        test_app_args = [str(binary_path)]
        test_app_args.extend(["--iter", str(event_count)])
        test_app_args.extend(
            ["--sync-application-in-main-touch", str(app_ready_file_path)]
        )
        test_app_args.extend(
            ["--sync-before-first-event", str(self._app_start_tracing_file_path)]
        )
        test_app_args.extend(
            [
                "--sync-before-last-event-touch",
                str(self._app_before_last_event_file_path),
            ]
        )
        test_app_args.extend(
            ["--sync-before-exit-touch", str(self._app_tracing_done_file_path)]
        )

        if wait_before_last_event:
            test_app_args.extend(
                [
                    "--sync-before-last-event",
                    str(self._wait_before_last_event_file_path),
                ]
            )

        if wait_before_exit:
            test_app_args.extend(
                ["--sync-before-exit", str(self._wait_before_exit_file_path)]
            )

        if wait_time_between_events_us != 0:
            test_app_args.extend(["--wait", str(wait_time_between_events_us)])

        if text_size is not None:
            test_app_args.extend(["--text-size", str(text_size)])

        if fill_text:
            test_app_args.extend(["--fill-text"])

        if run_as is not None:
            # When running as root and reducing the permissions to run as another
            # user, the test binary needs to be readable and executable by the
            # world; however, the file may be in a deep path or on systems where
            # we don't want to modify the filesystem state (eg. for a person who
            # has downloaded and ran the tests manually).
            # Therefore, the binary_path is copied to a temporary file in the
            # `run_as` user's home directory
            new_binary_path = os.path.join(
                str(environment.lttng_home_location),
                run_as,
                os.path.basename(str(binary_path)),
            )

            if not os.path.exists(new_binary_path):
                shutil.copy(str(binary_path), new_binary_path)

            test_app_args[0] = new_binary_path

            lib_dir = environment.lttng_home_location / run_as / "lib"
            if not os.path.isdir(str(lib_dir)):
                os.mkdir(str(lib_dir))
                # When running dropping privileges, the libraries built in the
                # root-owned directories may not be reachable and readable by
                # the loader running as an unprivileged user. These should also be
                # copied.
                _ldd = subprocess.Popen(
                    ["ldd", new_binary_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                if _ldd.wait() != 0:
                    raise RuntimeError(
                        "Error while using `ldd` to determine test application dependencies: `{}`".format(
                            stderr.read().decode("utf-8")
                        )
                    )
                libs = [
                    x.decode("utf-8").split(sep="=>") for x in _ldd.stdout.readlines()
                ]
                libs = [
                    x[1].split(sep=" ")[1]
                    for x in libs
                    if len(x) >= 2 and x[1].find("lttng") != -1
                ]
                for lib in libs:
                    shutil.copy(lib, lib_dir)

            test_app_env["LD_LIBRARY_PATH"] = "{}:{}".format(
                test_app_env.get("LD_LIBRARY_PATH", ""),
                str(lib_dir),
            )

            # As of python 3.9, subprocess.Popen supports a user parameter which
            # runs `setreuid()` before executing the proces and will be preferable
            # when support for older python versions is no longer required.
            test_app_args = [
                "runuser",
                "-u",
                run_as,
                "--",
            ] + test_app_args

        self._environment._log(
            "Launching test application: '{}'".format(
                self._compat_shlex_join(test_app_args)
            )
        )
        self._process = subprocess.Popen(
            test_app_args,
            env=test_app_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )  # type: subprocess.Popen

        # Create and start a thread to consume and log the process output
        if self._environment._logging_function:
            self._output_consumer = ProcessOutputConsumer(
                self._process,
                "test-app-{}".format(os.path.basename(str(test_app_args[0]))),
                self._environment._logging_function,
            )
            self._output_consumer.daemon = True
            self._output_consumer.start()
        else:
            self._output_consumer = None

        # Wait for the application to create the file indicating it has fully
        # initialized. Make sure the app hasn't crashed in order to not wait
        # forever.
        self._wait_for_file_to_be_created(pathlib.Path(app_ready_file_path))

    def _wait_for_file_to_be_created(self, sync_file_path):
        # type: (pathlib.Path) -> None
        while True:
            if os.path.exists(self._compat_pathlike(sync_file_path)):
                break

            if self._process.poll() is not None:
                # Application has unexepectedly returned.
                raise RuntimeError(
                    "Test application has unexepectedly returned while waiting for synchronization file to be created: sync_file=`{sync_file}`, return_code=`{return_code}`, output=`{output}`".format(
                        sync_file=sync_file_path,
                        return_code=self._process.returncode,
                        output=self._process.stdout.read().decode("utf-8"),
                    )
                )

            time.sleep(0.001)

    def taskset(self, cpu):
        """
        Use taskset to set the CPU affinity for the traced application.
        """
        if not self.vpid:
            raise RuntimeError("No process ID")

        if self._has_returned:
            raise RuntimeError("Application is already marked as returned")

        p = subprocess.Popen(["taskset", "-p", "-c", str(cpu), str(self.vpid)])
        if p.wait() or p.returncode != 0:
            raise RuntimeError("taskset failed, return code: {}".format(p.returncode))

    def taskset_anycpu(self, retry=True):
        while True:
            try:
                self.taskset(list(online_cpus())[0])
                break
            except RuntimeError as e:
                if retry:
                    pass

    def touch_last_event_file(self):
        if self._wait_before_last_event_file_path is None:
            raise RuntimeError("wait_before_laswt_event_file_path not set")

        open(self._compat_pathlike(self._wait_before_last_event_file_path), mode="x")

    def touch_exit_file(self):
        open(self._compat_pathlike(self._wait_before_exit_file_path), mode="x")

    @property
    def start_tracing_path(self):
        return self._compat_pathlike(self._app_start_tracing_file_path)

    def trace(self):
        # type: () -> None
        if self._process.poll() is not None:
            # Application has unexepectedly returned.
            raise RuntimeError(
                "Test application has unexepectedly before tracing with return code `{return_code}`".format(
                    return_code=self._process.returncode
                )
            )
        open(self._compat_pathlike(self._app_start_tracing_file_path), mode="x")
        self._environment._log("[{}] Tracing started".format(self.vpid))
        self._tracing_started = True

    def wait_for_before_last_event(self):
        # type: () -> None
        if not self._tracing_started:
            raise RuntimeError("Tracing hasn't been started")
        self._wait_for_file_to_be_created(self._app_before_last_event_file_path)
        self._environment._log("[{}] Before last event done".format(self.vpid))

    def wait_for_tracing_done(self):
        # type: () -> None
        if not self._tracing_started:
            raise RuntimeError("Tracing hasn't been started")
        self._wait_for_file_to_be_created(self._app_tracing_done_file_path)
        self._environment._log("[{}] Tracing done".format(self.vpid))

    def wait_for_exit(self):
        # type: () -> None
        if self._process.wait() != 0:
            raise RuntimeError(
                "Test application [{pid}] has exit with return code `{return_code}`".format(
                    pid=self.vpid,
                    return_code=self._process.returncode,
                )
            )
        self._has_returned = True

    @property
    def status(self):
        return self._process.poll()

    @property
    def vpid(self):
        # type: () -> int
        return self._process.pid

    @staticmethod
    def _compat_pathlike(path):
        # type: (pathlib.Path) -> pathlib.Path | str
        """
        The builtin open() and many methods of the 'os' library in Python >= 3.6
        expect a path-like object while prior versions expect a string or
        bytes object. Return the correct type based on the presence of the
        "__fspath__" attribute specified in PEP-519.
        """
        if hasattr(path, "__fspath__"):
            return path
        else:
            return str(path)

    @staticmethod
    def _compat_shlex_join(args):
        # type: list[str] -> str
        # shlex.join was added in python 3.8
        return " ".join([shlex.quote(x) for x in args])

    def __del__(self):
        if self._process is not None and not self._has_returned:
            # This is potentially racy if the pid has been recycled. However,
            # we can't use pidfd_open since it is only available in python >= 3.9.
            self._process.kill()
            self._process.wait()


class WaitTraceTestApplicationGroup:
    def __init__(
        self,
        environment,  # type: Environment
        application_count,  # type: int
        event_count,  # type: int
        wait_time_between_events_us=0,  # type: int
        wait_before_exit=False,  # type: bool
    ):
        self._wait_before_exit_file_path = (
            pathlib.Path(
                tempfile.mktemp(
                    prefix="app_group_",
                    suffix="_exit",
                    dir=_WaitTraceTestApplication._compat_pathlike(
                        environment.lttng_home_location
                    ),
                )
            )
            if wait_before_exit
            else None
        )

        self._apps = []
        self._consumers = []
        for i in range(application_count):
            new_app = environment.launch_wait_trace_test_application(
                event_count,
                wait_time_between_events_us,
                wait_before_exit,
                self._wait_before_exit_file_path,
            )

            # Attach an output consumer to log the application's error output (if any).
            if environment._logging_function:
                app_output_consumer = ProcessOutputConsumer(
                    new_app._process,
                    "app-{}".format(str(new_app.vpid)),
                    environment._logging_function,
                )  # type: Optional[ProcessOutputConsumer]
                app_output_consumer.daemon = True
                app_output_consumer.start()
                self._consumers.append(app_output_consumer)

            self._apps.append(new_app)

    def trace(self):
        # type: () -> None
        for app in self._apps:
            app.trace()

    def exit(
        self, wait_for_apps=False  # type: bool
    ):
        if self._wait_before_exit_file_path is None:
            raise RuntimeError(
                "Can't call exit on an application group created with `wait_before_exit=False`"
            )

        # Wait for apps to have produced all of their events so that we can
        # cause the death of all apps to happen within a short time span.
        for app in self._apps:
            app.wait_for_tracing_done()

        self._apps[0].touch_exit_file()

        # Performed in two passes to allow tests to stress the unregistration of many applications.
        # Waiting for each app to exit turn-by-turn would defeat the purpose here.
        if wait_for_apps:
            for app in self._apps:
                app.wait_for_exit()


class _TraceTestApplication:
    """
    Create an application that emits events as soon as it is launched. In most
    scenarios, it is preferable to use a WaitTraceTestApplication.
    """

    def __init__(self, binary_path, environment, extra_env_vars=dict(), **kwargs):
        # type: (pathlib.Path, Environment)
        self._process = None
        self._environment = environment  # type: Environment
        self._has_returned = False

        test_app_env = os.environ.copy()
        test_app_env["LTTNG_HOME"] = str(environment.lttng_home_location)
        if environment.lttng_rundir is not None:
            test_app_env["LTTNG_UST_APP_PATH"] = str(environment.lttng_rundir)

        # Make sure the app is blocked until it is properly registered to
        # the session daemon.
        test_app_env["LTTNG_UST_REGISTER_TIMEOUT"] = "-1"
        if type(binary_path) is str:
            test_app_args = [str(binary_path)]
        else:
            # Assume it is a list
            test_app_args = binary_path

        test_app_env.update(extra_env_vars)
        self._process = subprocess.Popen(
            test_app_args, env=test_app_env, **kwargs
        )  # type: subprocess.Popen
        self._environment._log(
            "Launched tested application '{}' with pid '{}'".format(
                test_app_args, self._process.pid
            )
        )

    def wait_for_exit(self):
        # type: () -> None
        if self._process.wait() != 0:
            raise RuntimeError(
                "Test application has exit with return code `{return_code}`".format(
                    return_code=self._process.returncode
                )
            )
        self._has_returned = True

    def __del__(self):
        if self._process is not None and not self._has_returned:
            # This is potentially racy if the pid has been recycled. However,
            # we can't use pidfd_open since it is only available in python >= 3.9.
            self._environment._log(
                "Terminating test app pid '{}'".format(self._process.pid)
            )
            self._process.terminate()
            try:
                self._process.wait(timeout=self._environment.teardown_timeout)
            except TimeoutException:
                self._environment._log(
                    "Killing test app pid '{}'".format(self._process.pid)
                )
                self._process.kill()


class ProcessOutputConsumer(threading.Thread, logger._Logger):
    def __init__(
        self,
        process,  # type: subprocess.Popen
        name,  # type: str
        log,  # type: Callable[[str], None]
    ):
        threading.Thread.__init__(self)
        self._prefix = name
        logger._Logger.__init__(self, log)
        self._process = process

    def run(self):
        # type: () -> None
        while self._process.poll() is None:
            if not self._process.stdout:
                break
            line = self._process.stdout.readline().decode("utf-8").replace("\n", "")
            if len(line) != 0:
                self._log("{prefix}: {line}".format(prefix=self._prefix, line=line))


class SavingProcessOutputConsumer(ProcessOutputConsumer):
    def __init__(self, process, name, log):
        self._lines = []
        super().__init__(process=process, name=name, log=log)

    def run(self):
        # type: () -> None
        while self._process.poll() is None:
            if not self._process.stdout:
                break
            line = self._process.stdout.readline().decode("utf-8").replace("\n", "")
            if len(line) != 0:
                self._lines.append(line)
                self._log("{prefix}: {line}".format(prefix=self._prefix, line=line))

    @property
    def output(self):
        return self._lines


# Generate a temporary environment in which to execute a test.
class _Environment(logger._Logger):
    def __init__(
        self,
        with_sessiond,  # type: bool
        log=None,  # type: Optional[Callable[[str], None]]
        with_relayd=False,  # type: bool
        extra_env_vars=dict(),  # type: dict
        skip_temporary_lttng_home=False,  # type: bool
        enable_kernel_domain=False,  # type: bool
        skip_temporary_lttng_rundir=False,  # type: bool
        sessiond_extra_args=None,  # type: Optional[List[str]]
    ):
        super().__init__(log)
        signal.signal(signal.SIGTERM, self._handle_termination_signal)
        signal.signal(signal.SIGINT, self._handle_termination_signal)

        if os.getenv("LTTNG_TEST_VERBOSE_BABELTRACE", "0") != "0":
            # @TODO: Is there a way to feed the logging output to
            # the logger._Logger instead of directly to stderr?
            bt2.set_global_logging_level(bt2.LoggingLevel.TRACE)

        # Assumes the project's hierarchy to this file is:
        # tests/utils/python/this_file
        self._project_root = (
            pathlib.Path(__file__).absolute().parents[3]
        )  # type: pathlib.Path

        self._extra_env_vars = extra_env_vars

        # There are times when we need to exercise default configurations
        # that don't set LTTNG_HOME. When doing this, it makes it impossible
        # to safely run parallel tests.
        self._lttng_home = None
        if not skip_temporary_lttng_home:
            self._lttng_home = TemporaryDirectory(
                "lttng_test_env_home"
            )  # type: Optional[TemporaryDirectory]
            os.chmod(
                str(self._lttng_home.path),
                stat.S_IRUSR
                | stat.S_IWUSR
                | stat.S_IXUSR
                | stat.S_IROTH
                | stat.S_IXOTH,
            )

        # When starting a sessiond daemon with the root user, the rundir
        # is global by default. Use LTTNG_RUNDIR to set it to a temporary
        # directory to avoid trampling on parallel tests.
        self._lttng_rundir = None
        if os.getuid() == 0 and not skip_temporary_lttng_rundir:
            self._lttng_rundir = TemporaryDirectory("lttng_test_env_rundir")
            self._extra_env_vars["LTTNG_RUNDIR"] = str(self._lttng_rundir.path)

        self._preserve_test_env = os.getenv("LTTNG_TEST_PRESERVE_TEST_ENV", "0") != "1"
        self._relayd_control_port = 0
        self._relayd_data_port = 0
        self._relayd_live_port = 0
        self._relayd_env_vars = {}
        self._relayd = None
        self._relayd_output_consumer = None
        self._dummy_users = {}  # type: Dictionary[int, string]
        self.teardown_timeout = os.getenv("LTTNG_TEST_TEARDOWN_TIMEOUT", "60")
        self._sessiond = None
        self._sessiond_extra_args = sessiond_extra_args if sessiond_extra_args else []

        # Start daemons as required
        self._relayd = (
            self._launch_lttng_relayd() if with_relayd else None
        )  # type: Optional[subprocess.Popen[bytes]]
        self._sessiond = (
            self._launch_lttng_sessiond(enable_kernel_domain) if with_sessiond else None
        )  # type: Optional[subprocess.Popen[bytes]]

        # This is a bit of particularity for the testing infrastructure.
        # When the sessiond is started, it will change the permissions of the
        # set LTTNG_RUNDIR. When running tests that exercise a traced application
        # run as a non-root user, it is convenient that the permissions are set
        # so that the shm wait file in LTTNG_UST_APP_PATH can be created.
        #
        # The behaviour of a traced application is to disable the LTTNG_UST_APP_PATH
        # connection if the shm wait file cannot be created, and subsequent retries
        # only attempt connections to the global socket in /var/run/lttng/.
        if self._lttng_rundir is not None:
            os.chmod(
                str(self._lttng_rundir.path),
                stat.S_IRUSR
                | stat.S_IWUSR
                | stat.S_IXUSR
                | stat.S_IROTH
                | stat.S_IWOTH
                | stat.S_IXOTH,
            )

    @property
    def teardown_timeout(self):
        return self._teardown_timeout

    @teardown_timeout.setter
    def teardown_timeout(self, value):
        try:
            self._teardown_timeout = int(value)
        except TypeError:
            self._teardown_timeout = None
        except ValueError:
            self._teardown_timeout = None

    @property
    def lttng_home_location(self):
        # type: () -> pathlib.Path
        if self._lttng_home is not None:
            return self._lttng_home.path
        return None

    @property
    def lttng_log_dir(self):
        path = os.getenv("LTTNG_TEST_LOG_DIR", "")
        if path == "" or path is None or path == "-":
            return None
        return path

    @property
    def lttng_rundir(self):
        # type: () -> pathlib.Path
        if self._lttng_rundir is not None:
            return self._lttng_rundir.path
        return None

    @property
    def lttng_client_path(self):
        # type: () -> pathlib.Path
        return self._project_root / "src" / "bin" / "lttng" / "lttng"

    def _relayd_port(self, port_name):
        port_attr = "_relayd_{}_port".format(port_name)
        if getattr(self, port_attr) == 0:
            try:
                self._update_relayd_port(port_name)
            except Exception:
                pass
        return getattr(self, port_attr)

    def _update_relayd_port(self, port_name):
        port_attr = "_relayd_{}_port".format(port_name)
        port_file = self.lttng_relayd_control_directory / "{}.port".format(port_name)
        try:
            with open(str(port_file), "r") as f:
                setattr(self, port_attr, int(f.read()))
        except Exception as e:
            self._log("Failed to open port file '{}': {}".format(port_file, str(e)))
            raise e

    @property
    def lttng_relayd_control_port(self):
        # type: () -> int
        return self._relayd_port("control")

    @property
    def lttng_relayd_data_port(self):
        # type: () -> int
        return self._relayd_port("data")

    @property
    def lttng_relayd_live_port(self):
        # type: () -> int
        return self._relayd_port("live")

    @property
    def lttng_relayd_control_directory(self):
        if self.lttng_relayd_env_vars.get("LTTNG_RUNDIR"):
            return (
                pathlib.Path(self.lttng_relayd_env_vars.get("LTTNG_RUNDIR")) / "relayd"
            )
        else:
            home_dir = (
                self.lttng_relayd_env_vars["LTTNG_HOME"]
                if ("LTTNG_HOME" in self.lttng_relayd_env_vars)
                else os.environ.get("HOME", os.path.expanduser("~"))
            )
            return (
                pathlib.Path("/var/run/lttng")
                if os.getuid() == 0
                else pathlib.Path(home_dir) / ".lttng"
            ) / "relayd"

    @property
    def lttng_relayd_env_vars(self):
        return self._relayd_env_vars

    @property
    def lttng_relayd_output_path(self):
        return os.path.join(
            (
                str(self.lttng_home_location)
                if self.lttng_home_location
                else os.getenv("HOME")
            ),
            "lttng-traces",
            platform.node(),
        )

    @property
    def preserve_test_env(self):
        # type: () -> bool
        return self._preserve_test_env

    @staticmethod
    def allows_destructive():
        # type: () -> bool
        return os.getenv("LTTNG_ENABLE_DESTRUCTIVE_TESTS", "") == "will-break-my-system"

    def create_dummy_user(self):
        # type: () -> (int, str)
        # Create a dummy user. The uid and username will be returned in a tuple.
        # If the name already exists, an exception will be thrown.
        # The users will be removed when the environment is cleaned up.
        name = "".join([random.choice(string.ascii_lowercase) for x in range(10)])

        try:
            entry = pwd.getpwnam(name)
            raise Exception("User '{}' already exists".format(name))
        except KeyError:
            pass

        # Create user
        proc = subprocess.Popen(
            [
                "useradd",
                "--base-dir",
                str(self._lttng_home.path),
                "--create-home",
                "--no-user-group",
                "--shell",
                "/bin/sh",
                name,
            ]
        )
        proc.wait()
        if proc.returncode != 0:
            raise Exception(
                "Failed to create user '{}', useradd returned {}".format(
                    name, proc.returncode
                )
            )

        entry = pwd.getpwnam(name)
        self._dummy_users[entry[2]] = name
        return (entry[2], name)

    def create_temporary_directory(self, prefix=None):
        # type: (Optional[str]) -> pathlib.Path
        # Simply return a path that is contained within LTTNG_HOME; it will
        # be destroyed when the temporary home goes out of scope.
        return pathlib.Path(
            tempfile.mkdtemp(
                prefix="tmp" if prefix is None else prefix,
                dir=str(self.lttng_home_location) if self.lttng_home_location else None,
            )
        )

    @staticmethod
    def run_kernel_tests():
        # type: () -> bool
        return (
            os.getenv("LTTNG_TOOLS_DISABLE_KERNEL_TESTS", "0") != "1"
            and os.getuid() == 0
        )

    @staticmethod
    def run_long_regression_tests():
        # type: () -> bool
        value = os.getenv("LTTNG_TOOLS_RUN_TESTS_LONG_REGRESSION")
        return bool(value and value != "0")

    # Unpack a list of environment variables from a string
    # such as "HELLO=is_it ME='/you/are/looking/for'"
    @staticmethod
    def _unpack_env_vars(env_vars_string):
        # type: (str) -> List[Tuple[str, str]]
        unpacked_vars = []
        for var in shlex.split(env_vars_string):
            equal_position = var.find("=")
            # Must have an equal sign and not end with an equal sign
            if equal_position == -1 or equal_position == len(var) - 1:
                raise ValueError(
                    "Invalid sessiond environment variable: `{}`".format(var)
                )

            var_name = var[0:equal_position]
            var_value = var[equal_position + 1 :]
            # Unquote any paths
            var_value = var_value.replace("'", "")
            var_value = var_value.replace('"', "")
            unpacked_vars.append((var_name, var_value))

        return unpacked_vars

    def _launch_lttng_relayd(self):
        # type: () -> Optional[subprocess.Popen]
        relayd_path = (
            self._project_root / "src" / "bin" / "lttng-relayd" / "lttng-relayd"
        )
        if os.environ.get("LTTNG_TEST_NO_RELAYD", "0") == "1":
            # Run without a relay daemon; the user may be running one
            # under gdb, for example.
            return None

        relayd_env_vars = os.environ.get("LTTNG_RELAYD_ENV_VARS")
        relayd_env = os.environ.copy()
        relayd_env.update(self._extra_env_vars)
        if relayd_env_vars:
            self._log("Additional lttng-relayd environment variables:")
            for name, value in self._unpack_env_vars(relayd_env_vars):
                self._log("{}={}".format(name, value))
                relayd_env[name] = value

        if self.lttng_home_location is not None:
            relayd_env["LTTNG_HOME"] = str(self.lttng_home_location)

        self._relayd_env_vars = relayd_env
        self._log(
            "Launching relayd with LTTNG_HOME='{}'".format(
                str(self.lttng_home_location)
            )
        )

        verbose = []
        if os.getenv("LTTNG_TEST_VERBOSE_RELAYD", "0") != "0":
            verbose = ["-vvv"]
        self._relayd_log_file = None
        if self.lttng_log_dir:
            self._relayd_log_file = tempfile.NamedTemporaryFile(
                prefix="relayd_",
                dir=self.lttng_log_dir,
                delete=False,
            )
        process = subprocess.Popen(
            [
                str(relayd_path),
                "--dynamic-port-allocation",
                "-C",
                "tcp://0.0.0.0:{}".format(self.lttng_relayd_control_port),
                "-D",
                "tcp://0.0.0.0:{}".format(self.lttng_relayd_data_port),
                "-L",
                "tcp://localhost:{}".format(self.lttng_relayd_live_port),
            ]
            + verbose,
            stdout=(
                self._relayd_log_file.file if self._relayd_log_file else subprocess.PIPE
            ),
            stderr=subprocess.STDOUT,
            env=relayd_env,
        )

        if self._logging_function:
            self._relayd_output_consumer = ProcessOutputConsumer(
                process, "lttng-relayd", self._logging_function
            )
            self._relayd_output_consumer.daemon = True
            self._relayd_output_consumer.start()

        if os.environ.get("LTTNG_TEST_GDBSERVER_RELAYD") is not None:
            subprocess.Popen(
                [
                    "gdbserver",
                    "--attach",
                    "localhost:{}".format(
                        os.environ.get("LTTNG_TEST_GDBSERVER_RELAYD_PORT", "1025")
                    ),
                    str(process.pid),
                ]
            )

            if os.environ.get("LTTNG_TEST_GDBSERVER_RELAYD_WAIT", ""):
                input("Waiting for user input. Press `Enter` to continue")
            else:
                subprocess.Popen(
                    [
                        "gdb",
                        "--batch-silent",
                        "-ex",
                        "target remote localhost:{}".format(
                            os.environ.get("LTTNG_TEST_GDBSERVER_RELAYD_PORT", "1025")
                        ),
                        "-ex",
                        "continue",
                        "-ex",
                        "disconnect",
                    ]
                )

        # Wait until the ports are written to the run directory
        self._log(
            "Checking for relayd port files in '{}'".format(
                self.lttng_relayd_control_directory
            )
        )
        while (
            self.lttng_relayd_control_port == 0
            or self.lttng_relayd_live_port == 0
            or self.lttng_relayd_data_port == 0
        ):
            self._log(
                "Waiting for lttng-relayd control ({}), data ({}), and live ({}) ports to be non-zero".format(
                    self.lttng_relayd_control_port,
                    self.lttng_relayd_data_port,
                    self.lttng_relayd_live_port,
                )
            )
            time.sleep(0.1)
        self._log(
            "lttng-relayd using the following ports: control {}, data {}, and live {}".format(
                self.lttng_relayd_control_port,
                self.lttng_relayd_data_port,
                self.lttng_relayd_live_port,
            )
        )

        return process

    def _launch_lttng_sessiond(self, enable_kernel_domain=False):
        # type: () -> Optional[subprocess.Popen]
        is_64bits_host = sys.maxsize > 2**32

        sessiond_path = (
            self._project_root / "src" / "bin" / "lttng-sessiond" / "lttng-sessiond"
        )
        consumerd_path_option_name = "--consumerd{bitness}-path".format(
            bitness="64" if is_64bits_host else "32"
        )
        consumerd_path = (
            self._project_root / "src" / "bin" / "lttng-consumerd" / "lttng-consumerd"
        )

        no_sessiond_var = os.environ.get("TEST_NO_SESSIOND")
        if no_sessiond_var and no_sessiond_var == "1":
            # Run test without a session daemon; the user probably
            # intends to run one under gdb for example.
            return None

        # Setup the session daemon's environment
        sessiond_env_vars = os.environ.get("LTTNG_SESSIOND_ENV_VARS")
        sessiond_env = os.environ.copy()
        sessiond_env.update(self._extra_env_vars)
        if sessiond_env_vars:
            self._log("Additional lttng-sessiond environment variables:")
            additional_vars = self._unpack_env_vars(sessiond_env_vars)
            for var_name, var_value in additional_vars:
                self._log("  {name}={value}".format(name=var_name, value=var_value))
                sessiond_env[var_name] = var_value

        sessiond_env["LTTNG_SESSION_CONFIG_XSD_PATH"] = str(
            self._project_root / "src" / "common"
        )

        if self.lttng_home_location is not None:
            sessiond_env["LTTNG_HOME"] = str(self.lttng_home_location)

        wait_queue = _SignalWaitQueue()
        with wait_queue.intercept_signal(signal.SIGUSR1):
            self._log(
                "Launching session daemon with LTTNG_HOME=`{home_dir}`".format(
                    home_dir=str(self.lttng_home_location)
                )
            )
            verbose = []
            sessiond_command = [
                str(sessiond_path),
                consumerd_path_option_name,
                str(consumerd_path),
                "--sig-parent",
            ]
            if os.getenv("LTTNG_TEST_VERBOSE_SESSIOND", "0") != "0":
                sessiond_command.extend(["-vvv", "--verbose-consumer"])
            if not enable_kernel_domain:
                sessiond_command.extend(["--no-kernel"])
            if self._sessiond_extra_args:
                sessiond_command.extend(self._sessiond_extra_args)
            self._lttng_sessiond_log_file = None
            if self.lttng_log_dir:
                self._lttng_sessiond_log_file = tempfile.NamedTemporaryFile(
                    prefix="sessiond_",
                    dir=self.lttng_log_dir,
                    delete=False,
                )

            self._log(" ".join(sessiond_command))
            process = subprocess.Popen(
                sessiond_command,
                stdout=(
                    self._lttng_sessiond_log_file.file
                    if self._lttng_sessiond_log_file
                    else subprocess.PIPE
                ),
                stderr=subprocess.STDOUT,
                env=sessiond_env,
            )

            if self._logging_function:
                self._sessiond_output_consumer = ProcessOutputConsumer(
                    process, "lttng-sessiond", self._logging_function
                )  # type: Optional[ProcessOutputConsumer]
                self._sessiond_output_consumer.daemon = True
                self._sessiond_output_consumer.start()

            # Wait for SIGUSR1, indicating the sessiond is ready to proceed
            wait_queue.wait_for_signal()

        if os.environ.get("LTTNG_TEST_GDBSERVER_SESSIOND") is not None:
            subprocess.Popen(
                [
                    "gdbserver",
                    "--attach",
                    "localhost:{}".format(
                        os.environ.get("LTTNG_TEST_GDBSERVER_SESSIOND_PORT", "1024")
                    ),
                    str(process.pid),
                ]
            )

            if os.environ.get("LTTNG_TEST_GDBSERVER_SESSIOND_WAIT", ""):
                input("Waiting for user input. Press `Enter` to continue")
            else:
                subprocess.Popen(
                    [
                        "gdb",
                        "--batch-silent",
                        "-ex",
                        "target remote localhost:{}".format(
                            os.environ.get("LTTNG_TEST_GDBSERVER_SESSIOND_PORT", "1024")
                        ),
                        "-ex",
                        "continue",
                        "-ex",
                        "disconnect",
                    ]
                )

        return process

    def _handle_termination_signal(self, signal_number, frame):
        # type: (int, Optional[FrameType]) -> None
        if sys.version_info[0] == 3 and sys.version_info[1] >= 8:
            # signal.strsignal is introduced in python 3.8
            self._log(
                "Killed by {signal_name} signal, cleaning-up".format(
                    signal_name=signal.strsignal(signal_number)
                )
            )
        else:
            self._log("Killed by signal {}, cleaning-up".format(str(signal_number)))
        self._cleanup()

    def launch_live_viewer(self, session, hostname=None):
        # Make sure the relayd is ready
        ready = False
        ctf_live_cc = bt2.find_plugin("ctf").source_component_classes["lttng-live"]
        query_executor = bt2.QueryExecutor(
            ctf_live_cc,
            "sessions",
            params={"url": "net://localhost:{}".format(self.lttng_relayd_live_port)},
        )
        while not ready:
            try:
                query_result = query_executor.query()
            except bt2._Error:
                time.sleep(0.1)
                continue
            for live_session in query_result:
                if live_session["session-name"] == session:
                    ready = True
                    self._log(
                        "Session '{}' is available at net://localhost:{}".format(
                            session, self.lttng_relayd_live_port
                        )
                    )
                    break
        return _LiveViewer(self, session, hostname)

    def launch_wait_trace_test_application(
        self,
        event_count,  # type: int
        wait_time_between_events_us=0,
        wait_before_exit=False,
        wait_before_exit_file_path=None,
        run_as=None,
        text_size=None,
        fill_text=False,
        wait_before_last_event=False,
        wait_before_last_event_file_path=None,
        extra_env_vars=dict(),
    ):
        # type: (int, int, bool, Optional[pathlib.Path], Optional[str]) -> _WaitTraceTestApplication
        """
        Launch an application that will wait before tracing `event_count` events.
        """
        return _WaitTraceTestApplication(
            self._project_root / "tests" / "utils" / "testapp" / "gen-ust-events",
            event_count,
            self,
            wait_time_between_events_us,
            wait_before_exit,
            wait_before_exit_file_path,
            run_as,
            text_size,
            fill_text,
            wait_before_last_event,
            wait_before_last_event_file_path,
            extra_env_vars,
        )

    def launch_test_application(self, path, extra_env_vars=dict(), **kwargs):
        # type () -> TraceTestApplication
        """
        Launch an application with it's environment set for being traced
        by this test environment's session daemon.
        """
        return _TraceTestApplication(
            path,
            self,
            extra_env_vars,
            **kwargs,
        )

    def _terminate_relayd(self):
        if self._relayd and self._relayd.poll() is None:
            try:
                self._relayd.terminate()
                self._log(
                    "Termination signal sent to relayd (pid = {})".format(
                        self._relayd.pid
                    )
                )
                self._relayd.wait(timeout=self.teardown_timeout)
            except subprocess.TimeoutExpired:
                self._relayd.kill()
                self._log(
                    "Kill signal sent to relayd (pid = {}) after waiting {}s".format(
                        self._relayd.pid, self.teardown_timeout
                    )
                )

            if self._relayd_output_consumer:
                self._relayd_output_consumer.join()
                self._relayd_output_consumer = None
            self._log("Relayd killed")
            self._relayd = None

    # Clean-up managed processes
    def _cleanup(self):
        # type: () -> None
        if self._sessiond and self._sessiond.poll() is None:
            # The session daemon is alive; kill it.
            try:
                self._sessiond.terminate()
                self._log(
                    "Termination signal sent to session daemon (pid = {})".format(
                        self._sessiond.pid
                    )
                )
                self._sessiond.wait(timeout=self.teardown_timeout)
            except subprocess.TimeoutExpired:
                self._sessiond.kill()
                self._log(
                    "Kill signal sent to lttng-sessiond (pid = {}) after waiting {}s".format(
                        self._sessiond.pid, self.teardown_timeout
                    )
                )
            if self._sessiond_output_consumer:
                self._sessiond_output_consumer.join()
                self._sessiond_output_consumer = None

            self._log("Session daemon killed")
            self._sessiond = None

        self._terminate_relayd()

        # The user accounts will always be deleted, but the home directories will
        # be retained unless the user has opted to preserve the test environment.
        userdel = ["userdel"]
        if not self.preserve_test_env:
            userdel += ["--remove"]
        for uid, name in self._dummy_users.items():
            # When subprocess is run during the interpreter teardown, ImportError
            # may be raised; however, the commands seem to execute correctly.
            # Eg.
            #
            # Exception ignored in: <function _Environment.__del__ at 0x7f2d62e3b9c0>
            # Traceback (most recent call last):
            #   File "tests/utils/lttngtest/environment.py", line 1024, in __del__
            #   File "tests/utils/lttngtest/environment.py", line 1016, in _cleanup
            #   File "/usr/lib/python3.11/subprocess.py", line 1026, in __init__
            #   File "/usr/lib/python3.11/subprocess.py", line 1880, in _execute_child
            #   File "<frozen os>", line 629, in get_exec_path
            # ImportError: sys.meta_path is None, Python is likely shutting down
            #
            try:
                _proc = subprocess.Popen(
                    ["pkill", "--uid", str(uid)], stderr=subprocess.PIPE
                )
                _proc.wait()
            except ImportError:
                pass
            try:
                _proc = subprocess.Popen(userdel + [name], stderr=subprocess.PIPE)
                _proc.wait()
            except ImportError:
                pass

        self._lttng_home = None

    def __del__(self):
        self._cleanup()


def getconf(name):
    p = subprocess.Popen(["getconf", str(name)], stdout=subprocess.PIPE)
    if p.wait() != 0:
        raise subprocess.CalledProcessError(
            returncode=p.returncode, cmd=["getconf", str(name)]
        )
    return p.stdout.read().decode("utf-8").strip()


def get_machine():
    """
    Returns a machine identifier
    """
    return "{}-{}".format(platform.machine(), platform.system().lower())


def count_events(trace_path, ignore_exceptions=False):
    """
    Returns a tuple of (received events, discarded events) from the trace path.

    trace_path may be an iterable (e.g., array, map from pathlib.Path.glob()).
    """
    received = 0
    discarded = 0
    dirs = []
    if isinstance(trace_path, str) or isinstance(trace_path, pathlib.Path):
        dirs.append(str(trace_path))
    else:
        dirs = trace_path

    for dir in dirs:
        try:
            for msg in bt2.TraceCollectionMessageIterator(str(dir)):
                if type(msg) is bt2._EventMessageConst:
                    received += 1
                if type(msg) is bt2._DiscardedEventsMessageConst:
                    # msg.count may be None when the value is indeterminate
                    discarded += msg.count if msg.count is not None else 1
        except Exception as e:
            if not ignore_exceptions:
                raise e

    return (received, discarded)


def count_events_worker(args):
    trace_path = args
    received = 0
    discarded = 0
    for msg in bt2.TraceCollectionMessageIterator(str(trace_path)):
        if type(msg) is bt2._EventMessageConst:
            received += 1
            continue

        if type(msg) is bt2._DiscardedEventsMessageConst:
            discarded += msg.count if msg.count is not None else 1

    return (received, discarded)


def parallel_count_events(trace_path, test_env):
    """
    Count the number of events in a trace using parallel processing.
    This is a workaround for the performance issues with bt2 bindings.

    trace_path may be an iterable (e.g., array, map from pathlib.Path.glob()).

    When multiple trace_paths are given, each one is handled iteratively, but
    the processing of each stream is farmed out to a worker.
    """
    dirs = []
    received = 0
    discarded = 0

    if isinstance(trace_path, str) or isinstance(trace_path, pathlib.Path):
        dirs.append(str(trace_path))
    else:
        dirs = trace_path

    for dir in dirs:
        streams_path = None
        for root, dirs, files in os.walk(str(dir)):
            if "metadata" in files:
                streams_path = pathlib.Path(root)
                break

        if streams_path is None:
            raise RuntimeError("No metadata found in trace path: {}".format(trace_path))

        metadata_path = streams_path / "metadata"
        stream_dirs = []

        for file in streams_path.iterdir():
            if file.name == "metadata":
                continue

            temp_dir_path = test_env.create_temporary_directory()

            # Symlink to the stream file
            stream_link = temp_dir_path / file.name
            stream_link.symlink_to(file)
            # Symlink to the metadata file
            metadata_link = temp_dir_path / "metadata"
            metadata_link.symlink_to(metadata_path)

            stream_dirs.append(temp_dir_path)

        with multiprocessing.Pool() as pool:
            results = pool.map(count_events_worker, stream_dirs)

        for this_received, this_discarded in results:
            received += this_received
            discarded += this_discarded

    return received, discarded


@contextlib.contextmanager
def kernel_module(module_name):
    """
    Context manager to load a kernel module and unload it when it goes out of scope.
    """
    try:
        subprocess.run(["modprobe", module_name], check=True)
        yield module_name
    finally:
        subprocess.run(["modprobe", "-r", module_name], check=True)


def online_cpus():
    "Return a set of CPU that are currently online."
    with open("/sys/devices/system/cpu/online") as online:
        cpus = set()

        for cpu_range in online.readline().split(","):
            if cpu_range.find("-") != -1:
                start, end = cpu_range.split("-")
                for cpu in range(int(start), int(end) + 1):
                    cpus.add(cpu)
            else:
                cpus.add(int(cpu_range.strip()))
        return cpus


@contextlib.contextmanager
def test_environment(
    with_sessiond,
    log=None,
    with_relayd=False,
    extra_env_vars=dict(),
    skip_temporary_lttng_home=False,
    enable_kernel_domain=False,
    skip_temporary_lttng_rundir=False,
    sessiond_extra_args=None,
):
    # type: (bool, Optional[Callable[[str], None]], bool, dict, bool, bool, bool, Optional[List[str]]) -> Iterator[_Environment]
    env = _Environment(
        with_sessiond,
        log,
        with_relayd,
        extra_env_vars,
        skip_temporary_lttng_home,
        enable_kernel_domain,
        skip_temporary_lttng_rundir,
        sessiond_extra_args,
    )
    try:
        yield env
    finally:
        env._cleanup()
