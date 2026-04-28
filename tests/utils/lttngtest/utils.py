#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

import logging
import shutil
import subprocess
import tempfile
import typing


def gdb_exists() -> bool:
    """Return True if GDB can be executed."""
    return shutil.which("gdb") is not None


def gdb_script(
    gdb_commands: typing.List[str],
    subprocess_kwargs: dict = dict(),
    breakpoint_pending: str = "on",
    pagination: str = "off",
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
