#!/usr/bin/env python3
#
# Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only
#

from types import FrameType
from typing import Callable, Iterator, Optional, Tuple, List
import sys
import pathlib
import signal
import subprocess
import shlex
import shutil
import os
import queue
import tempfile
from . import logger
import time
import threading
import contextlib


class TemporaryDirectory:
    def __init__(self, prefix):
        # type: (str) -> None
        self._directory_path = tempfile.mkdtemp(prefix=prefix)

    def __del__(self):
        shutil.rmtree(self._directory_path, ignore_errors=True)

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
        self._queue.get(block=True)


class WaitTraceTestApplication:
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
    ):
        self._environment = environment  # type: Environment
        if event_count % 5:
            # The test application currently produces 5 different events per iteration.
            raise ValueError("event count must be a multiple of 5")
        self._iteration_count = int(event_count / 5)  # type: int
        # File that the application will wait to see before tracing its events.
        self._app_start_tracing_file_path = pathlib.Path(
            tempfile.mktemp(
                prefix="app_",
                suffix="_start_tracing",
                dir=self._compat_open_path(environment.lttng_home_location),
            )
        )
        self._has_returned = False

        test_app_env = os.environ.copy()
        test_app_env["LTTNG_HOME"] = str(environment.lttng_home_location)
        # Make sure the app is blocked until it is properly registered to
        # the session daemon.
        test_app_env["LTTNG_UST_REGISTER_TIMEOUT"] = "-1"

        # File that the application will create to indicate it has completed its initialization.
        app_ready_file_path = tempfile.mktemp(
            prefix="app_",
            suffix="_ready",
            dir=self._compat_open_path(environment.lttng_home_location),
        )  # type: str

        test_app_args = [str(binary_path)]
        test_app_args.extend(
            shlex.split(
                "--iter {iteration_count} --create-in-main {app_ready_file_path} --wait-before-first-event {app_start_tracing_file_path} --wait {wait_time_between_events_us}".format(
                    iteration_count=self._iteration_count,
                    app_ready_file_path=app_ready_file_path,
                    app_start_tracing_file_path=self._app_start_tracing_file_path,
                    wait_time_between_events_us=wait_time_between_events_us,
                )
            )
        )

        self._process = subprocess.Popen(
            test_app_args,
            env=test_app_env,
        )  # type: subprocess.Popen

        # Wait for the application to create the file indicating it has fully
        # initialized. Make sure the app hasn't crashed in order to not wait
        # forever.
        while True:
            if os.path.exists(app_ready_file_path):
                break

            if self._process.poll() is not None:
                # Application has unexepectedly returned.
                raise RuntimeError(
                    "Test application has unexepectedly returned during its initialization with return code `{return_code}`".format(
                        return_code=self._process.returncode
                    )
                )

            time.sleep(0.1)

    def trace(self):
        # type: () -> None
        if self._process.poll() is not None:
            # Application has unexepectedly returned.
            raise RuntimeError(
                "Test application has unexepectedly before tracing with return code `{return_code}`".format(
                    return_code=self._process.returncode
                )
            )
        open(self._compat_open_path(self._app_start_tracing_file_path), mode="x")

    def wait_for_exit(self):
        # type: () -> None
        if self._process.wait() != 0:
            raise RuntimeError(
                "Test application has exit with return code `{return_code}`".format(
                    return_code=self._process.returncode
                )
            )
        self._has_returned = True

    @property
    def vpid(self):
        # type: () -> int
        return self._process.pid

    @staticmethod
    def _compat_open_path(path):
        # type: (pathlib.Path) -> pathlib.Path | str
        """
        The builtin open() in python >= 3.6 expects a path-like object while
        prior versions expect a string or bytes object. Return the correct type
        based on the presence of the "__fspath__" attribute specified in PEP-519.
        """
        if hasattr(path, "__fspath__"):
            return path
        else:
            return str(path)

    def __del__(self):
        if not self._has_returned:
            # This is potentially racy if the pid has been recycled. However,
            # we can't use pidfd_open since it is only available in python >= 3.9.
            self._process.kill()
            self._process.wait()


class TraceTestApplication:
    """
    Create an application to trace.
    """

    def __init__(self, binary_path, environment):
        # type: (pathlib.Path, Environment)
        self._environment = environment  # type: Environment
        self._has_returned = False

        test_app_env = os.environ.copy()
        test_app_env["LTTNG_HOME"] = str(environment.lttng_home_location)
        # Make sure the app is blocked until it is properly registered to
        # the session daemon.
        test_app_env["LTTNG_UST_REGISTER_TIMEOUT"] = "-1"

        test_app_args = [str(binary_path)]

        self._process: subprocess.Popen = subprocess.Popen(
            test_app_args, env=test_app_env
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
        if not self._has_returned:
            # This is potentially racy if the pid has been recycled. However,
            # we can't use pidfd_open since it is only available in python >= 3.9.
            self._process.kill()
            self._process.wait()


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
            assert self._process.stdout
            line = self._process.stdout.readline().decode("utf-8").replace("\n", "")
            if len(line) != 0:
                self._log("{prefix}: {line}".format(prefix=self._prefix, line=line))


# Generate a temporary environment in which to execute a test.
class _Environment(logger._Logger):
    def __init__(
        self,
        with_sessiond,  # type: bool
        log=None,  # type: Optional[Callable[[str], None]]
    ):
        super().__init__(log)
        signal.signal(signal.SIGTERM, self._handle_termination_signal)
        signal.signal(signal.SIGINT, self._handle_termination_signal)

        # Assumes the project's hierarchy to this file is:
        # tests/utils/python/this_file
        self._project_root = (
            pathlib.Path(__file__).absolute().parents[3]
        )  # type: pathlib.Path
        self._lttng_home = TemporaryDirectory(
            "lttng_test_env_home"
        )  # type: Optional[TemporaryDirectory]

        self._sessiond = (
            self._launch_lttng_sessiond() if with_sessiond else None
        )  # type: Optional[subprocess.Popen[bytes]]

    @property
    def lttng_home_location(self):
        # type: () -> pathlib.Path
        if self._lttng_home is None:
            raise RuntimeError("Attempt to access LTTng home after clean-up")
        return self._lttng_home.path

    @property
    def lttng_client_path(self):
        # type: () -> pathlib.Path
        return self._project_root / "src" / "bin" / "lttng" / "lttng"

    def create_temporary_directory(self, prefix=None):
        # type: (Optional[str]) -> pathlib.Path
        # Simply return a path that is contained within LTTNG_HOME; it will
        # be destroyed when the temporary home goes out of scope.
        assert self._lttng_home
        return pathlib.Path(
            tempfile.mkdtemp(
                prefix="tmp" if prefix is None else prefix,
                dir=str(self._lttng_home.path),
            )
        )

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

    def _launch_lttng_sessiond(self):
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
        if sessiond_env_vars:
            self._log("Additional lttng-sessiond environment variables:")
            additional_vars = self._unpack_env_vars(sessiond_env_vars)
            for var_name, var_value in additional_vars:
                self._log("  {name}={value}".format(name=var_name, value=var_value))
                sessiond_env[var_name] = var_value

        sessiond_env["LTTNG_SESSION_CONFIG_XSD_PATH"] = str(
            self._project_root / "src" / "common"
        )

        assert self._lttng_home is not None
        sessiond_env["LTTNG_HOME"] = str(self._lttng_home.path)

        wait_queue = _SignalWaitQueue()
        signal.signal(signal.SIGUSR1, wait_queue.signal)

        self._log(
            "Launching session daemon with LTTNG_HOME=`{home_dir}`".format(
                home_dir=str(self._lttng_home.path)
            )
        )
        process = subprocess.Popen(
            [
                str(sessiond_path),
                consumerd_path_option_name,
                str(consumerd_path),
                "--sig-parent",
            ],
            stdout=subprocess.PIPE,
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
        signal.signal(signal.SIGUSR1, wait_queue.signal)

        return process

    def _handle_termination_signal(self, signal_number, frame):
        # type: (int, Optional[FrameType]) -> None
        self._log(
            "Killed by {signal_name} signal, cleaning-up".format(
                signal_name=signal.strsignal(signal_number)
            )
        )
        self._cleanup()

    def launch_wait_trace_test_application(self, event_count):
        # type: (int) -> WaitTraceTestApplication
        """
        Launch an application that will wait before tracing `event_count` events.
        """
        return WaitTraceTestApplication(
            self._project_root
            / "tests"
            / "utils"
            / "testapp"
            / "gen-ust-nevents"
            / "gen-ust-nevents",
            event_count,
            self,
        )

    def launch_trace_test_constructor_application(self):
        # type () -> TraceTestApplication
        """
        Launch an application that will trace from within constructors.
        """
        return TraceTestApplication(
            self._project_root
            / "tests"
            / "utils"
            / "testapp"
            / "gen-ust-events-constructor"
            / "gen-ust-events-constructor",
            self,
        )

    # Clean-up managed processes
    def _cleanup(self):
        # type: () -> None
        if self._sessiond and self._sessiond.poll() is None:
            # The session daemon is alive; kill it.
            self._log(
                "Killing session daemon (pid = {sessiond_pid})".format(
                    sessiond_pid=self._sessiond.pid
                )
            )

            self._sessiond.terminate()
            self._sessiond.wait()
            if self._sessiond_output_consumer:
                self._sessiond_output_consumer.join()
                self._sessiond_output_consumer = None

            self._log("Session daemon killed")
            self._sessiond = None

        self._lttng_home = None

    def __del__(self):
        self._cleanup()


@contextlib.contextmanager
def test_environment(with_sessiond, log=None):
    # type: (bool, Optional[Callable[[str], None]]) -> Iterator[_Environment]
    env = _Environment(with_sessiond, log)
    try:
        yield env
    finally:
        env._cleanup()
