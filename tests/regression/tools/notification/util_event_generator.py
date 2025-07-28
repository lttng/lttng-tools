#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

import argparse
import os
import pathlib
import signal
import subprocess
import sys
import time

test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest

SYSCALL_TESTAPP_NAME = "gen-syscall-events"
SYSCALL_TESTAPP_BIN = None
USERSPACE_PROBE_ELF_TESTAPP_NAME = "userspace-probe-elf-binary"
USERSPACE_PROBE_ELF_TESTAPP_BIN = None
USERSPACE_TESTAPP_NAME = "gen-ust-events"
USERSPACE_TESTAPP_BIN = None

generator_suspended = False
generator_quit = False


def generate_filter_events(iterations, wait_us=None, generator_args=list()):
    with open("/proc/lttng-test-filter-event", "w") as f:
        f.write("{}".format(iterations))


def generate_syscalls(iterations, wait_us, generator_args=list()):
    global SYSCALL_TESTAPP_BIN

    env = os.environ.copy()
    env["LANG"] = "C"

    for i in range(iterations):
        cpus = list(lttngtest.online_cpus())

        while True:
            _args = [
                "taskset",
                "-c",
                str(cpus[0]),
                str(SYSCALL_TESTAPP_BIN),
                "/dev/null",
            ]
            _args.extend(generator_args)
            print(_args)
            process = subprocess.Popen(_args, stderr=subprocess.PIPE)
            if process.wait() != 0:
                errs = process.stderr.read().decode("utf-8")
                if errs.find("taskset: failed") != -1:
                    # If taskset fails, retry
                    print(
                        "Taskset failed with {} for application args {}".format(
                            p.returncode, _args
                        ),
                        file=sys.stderr,
                    )
                    print(errs, file=sys.stderr)
                    continue

            break


def generate_userspace_probe_testapp(iterations, wait_us=None, generator_args=list()):
    global USERSPACE_PROBE_ELF_TESTAPP_BIN
    lib_path = USERSPACE_PROBE_ELF_TESTAPP_BIN.parents[0]
    env = os.environ.copy()

    # This userspace probe test has to instrument the actual elf
    # binary and not the generated libtool wrapper. However, we
    # can't invoke the wrapper either since it will re-link the test
    # application binary on its first invocation, resulting in a new
    # binary with an 'lt-*' prefix under the .libs folder. The
    # relinking stage adds the .libs folder to the 'lt-*' binary's
    # rpath.
    #
    # To ensure the binary (inode) that instrumented is the same as
    # what is running, set LD_LIBRARY_PATH to find the .libs folder
    # that contains the libfoo.so library and invoke the binary
    # directly.
    ld_library_path = os.environ.get("LD_LIBRARY_PATH", "")
    if ld_library_path:
        ld_library_path += ":"
    ld_library_path += str(lib_path)
    env["LD_LIBRARY_PATH"] = ld_library_path

    _args = [str(USERSPACE_PROBE_ELF_TESTAPP_BIN)]
    _args.extend(generator_args)
    for i in range(iterations):
        subprocess.Popen(_args, env=env).wait()


def generate_userspace_testapp(iterations, wait_us=None, generator_args=list()):
    global USERSPACE_TESTAPP_BIN
    _args = [str(USERSPACE_TESTAPP_BIN), "-i", str(iterations), "-w", str(wait_us)]
    _args.extend(generator_args)
    # retry anycpu tasket
    subprocess.Popen(_args).wait()


def toggle_generator_state(signum, frame):
    global generator_suspended
    generator_suspended = not generator_suspended


def set_generator_quit(signum, frame):
    global generator_quit
    generator_quit = True


def event_generator(
    test_app_function,
    state_file,
    iterations=1000,
    wait_us=5,
    run_once=False,
    generator_args=list(),
    ready_file=None,
):
    global generator_suspended
    global generator_quit

    generator_suspended = False
    generator_quit = False
    run = False

    # Install signal handlers
    signal.signal(signal.SIGUSR1, toggle_generator_state)
    signal.signal(signal.SIGUSR2, set_generator_quit)
    if ready_file:
        ready_file.touch()

    while not generator_quit:
        if generator_suspended:
            if state_file:
                state_file.touch()
            run = True
            time.sleep(0.5)
        else:
            if run_once and not run:
                time.sleep(0.1)
                continue

            run = False
            test_app_function(
                iterations=iterations, wait_us=wait_us, generator_args=generator_args
            )
            if state_file and state_file.exists():
                state_file.unlink()

    # Uninstall signal handlers
    signal.signal(signal.SIGUSR1, signal.SIG_DFL)
    signal.signal(signal.SIGUSR2, signal.SIG_DFL)


if __name__ == "__main__":
    generators = {
        "kernel_generate_filter_events": generate_filter_events,
        "kernel_generate_syscalls": generate_syscalls,
        "userspace_probe_testapp": generate_userspace_probe_testapp,
        "userspace_testapp": generate_userspace_testapp,
    }

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--iterations", type=int, default=1000)
    parser.add_argument(
        "-w",
        "--wait",
        type=int,
        default=5,
        help="Number of microseconds to wait between events, if applicable",
    )
    parser.add_argument("--ready-file", type=pathlib.Path, default=None)
    parser.add_argument("--run-once", action="store_true", default=False)
    parser.add_argument("--state-file", type=pathlib.Path, default=None)
    parser.add_argument("generator_type", choices=generators.keys())
    parser.add_argument("rest", nargs="*")

    args = parser.parse_args()
    if os.environ.get("SYSCALL_TESTAPP_NAME", None):
        SYSCALL_TESTAPP_NAME = os.environ.get("SYSCALL_TESTAPP_NAME")

    if os.environ.get("SYSCALL_TESTAPP_BIN", None):
        SYSCALL_TESTAPP_BIN = os.environ.get("SYSCALL_TESTAPP_BIN")
    else:
        SYSCALL_TESTAPP_BIN = (
            test_utils_import_path.absolute()
            / "testapp"
            / SYSCALL_TESTAPP_NAME
        )

    if os.environ.get("USERSPACE_TESTAPP_NAME", None):
        USERSPACE_TESTAPP_NAME = os.environ.get("USERSPACE_TESTAPP_NAME")

    if os.environ.get("USERSPACE_TESTAPP_BIN", None):
        USERSPACE_TESTAPP_BIN = os.environ.get("USERSPACE_TESTAPP_BIN")
    else:
        USERSPACE_TESTAPP_BIN = (
            test_utils_import_path.absolute()
            / "testapp"
            / USERSPACE_TESTAPP_NAME
        )

    if os.environ.get("USERSPACE_PROBE_ELF_TESTAPP_NAME", None):
        USERSPACE_PROBE_ELF_TESTAPP_NAME = os.environ.get(
            "USERSPACE_PROBE_ELF_TESTAPP_NAME"
        )

    if os.environ.get("USERSPACE_PROBE_ELF_TESTAPP_BIN", None):
        USERSPACE_PROBE_ELF_TESTAPP_BIN = os.environ.get(
            "USERSPACE_PROBE_ELF_TESTAPP_BIN"
        )
    else:
        # For uprobe instrumented, it needs to the be the binary
        # itself, not the libtool wrapper.
        USERSPACE_PROBE_ELF_TESTAPP_BIN = (
            test_utils_import_path.absolute()
            / "testapp"
            / ".libs"
            / USERSPACE_PROBE_ELF_TESTAPP_NAME
        )

    print(
        "# Starting generator '{}', pid={}".format(args.generator_type, os.getpid()),
        file=sys.stderr,
    )
    event_generator(
        generators[args.generator_type],
        args.state_file,
        wait_us=args.wait,
        run_once=args.run_once,
        iterations=args.iterations,
        generator_args=args.rest,
        ready_file=args.ready_file,
    )
    print("# Generator pid={} done".format(os.getpid()), file=sys.stderr)
