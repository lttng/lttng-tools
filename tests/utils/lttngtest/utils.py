#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

import logging
import re
import shutil
import subprocess
import tempfile
import typing


def gdb_exists() -> bool:
    """Return True if GDB can be executed."""
    return shutil.which("gdb") is not None


def gdb_version() -> typing.Optional[typing.Tuple[int, int]]:
    """
    Return the (major, minor) version of the GDB found in PATH, or None
    if it cannot be determined.
    """
    try:
        output = subprocess.check_output(["gdb", "--version"], universal_newlines=True)
    except (OSError, subprocess.CalledProcessError):
        return None

    match = re.search(r"GNU gdb.*?(\d+)\.(\d+)", output)
    if match is None:
        return None

    return (int(match.group(1)), int(match.group(2)))


def gdb_set_logging_command(enabled: bool) -> str:
    """
    Return the GDB command to enable or disable logging.

    The `set logging enabled on|off` form was introduced in GDB 12; older
    versions (e.g. GDB 8.2 on EL8) only accept the deprecated
    `set logging on|off` form.
    """
    value = "on" if enabled else "off"
    version = gdb_version()
    if version is not None and version < (12, 0):
        return "set logging {}".format(value)

    return "set logging enabled {}".format(value)


def gdb_script(
    gdb_commands: typing.List[str],
    subprocess_kwargs: dict = dict(),
    breakpoint_pending: str = "on",
    pagination: str = "off",
    debug: bool = False,
) -> typing.Tuple[subprocess.Popen, tempfile.NamedTemporaryFile]:
    """
    Runs GDB commands as a batch script in a subprocess.

    Returns a tuple (subprocess object, tempfile). This is done
    since the tempfile needs to stay referenced until GDB is
    done, otherwise it may be deleted.
    """
    pre = [
        "set breakpoint pending {}".format(breakpoint_pending),
        "set pagination {}".format(pagination),
    ]
    if debug:
        # echo each command before it runs.
        echoed = []
        for command in gdb_commands:
            echoed.append("echo + {}\\n".format(command))
            echoed.append(command)

        gdb_commands = echoed

    commands = pre + gdb_commands
    script = tempfile.NamedTemporaryFile(
        prefix="gdb_",
    )
    logging.info("GDB script contents:")
    for command in commands:
        logging.info("  {}".format(command))

    # While NamedTemporaryFile() already returns a value that
    # can be used with write() without opening again, doing a
    # second open allows the context wrapper to perform a flush
    # and fsync before the subprocess is invoked.
    with open(script.name, "w") as f:
        f.write("\n".join(commands))

    gdb_args = ["gdb", "--nx", "--nw", "--batch", "-x", script.name]
    p = subprocess.Popen(gdb_args, **subprocess_kwargs)
    return (p, script)


def get_logging_format(tap: bool = True) -> str:
    return "{}[%(created)s] - %(levelname)s - %(message)s".format("# " if tap else "")
