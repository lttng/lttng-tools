#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Generate a representation of the ABI for the built liblttng-ctl library, and
diff against the stored copy, if any.
"""

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest


def test_abi_diff(tap, test_env):
    if not shutil.which("abidw") or not shutil.which("abidiff"):
        tap.skip("abidw and abidiff are not available")
        return

    if not shutil.which("gcc"):
        tap.skip("gcc is not available")
        return

    machine = lttngtest.get_machine()
    if not machine:
        tap.skip(
            "Couldn't determine machine triplet from gcc (got '{}')".format(machine)
        )
        return

    lttngctl_path = (
        pathlib.Path(test_env._project_root) / "src/lib/lttng-ctl/.libs/liblttng-ctl.so"
    )
    lttngctl_version = os.readlink(str(lttngctl_path)).split(".", 2)[-1]
    tap.diagnostic("Discovered liblttng-ctl version '{}'".format(lttngctl_version))

    abi_path = pathlib.Path(
        test_env._project_root
    ) / "src/lib/lttng-ctl/abi_ref/{}/{}/abi.xml".format(lttngctl_version, machine)

    headers_dir = pathlib.Path(test_env._project_root) / "include"

    if not lttngctl_path.exists():
        tap.skip("'{}' does not exist".format(str(lttngctl_path)))
        return

    if not abi_path.exists():
        tap.skip("'{}' does not exist".format(str(abi_path)))
        return

    abi_tmp = tempfile.NamedTemporaryFile()
    abidw_command = [
        "abidw",
        "--drop-undefined-syms",
        "--drop-private-types",
        "--headers-dir",
        str(headers_dir),
        str(lttngctl_path),
    ]

    tap.diagnostic("Generation command: `{}`".format(" ".join(abidw_command)))
    abidw = subprocess.Popen(
        abidw_command,
        stdout=abi_tmp.file,
        stderr=subprocess.PIPE,
    )
    abidw.wait()
    if abidw.returncode != 0:
        tap.diagnostic(abidw.stderr.read().decode("utf-8"))
        tap.fail(
            "Failed to produce XML representation of current ABI, returncode '{}'".format(
                abidw.returncode
            )
        )
        return

    abidiff_command = ["abidiff", str(abi_path), str(abi_tmp.name)]
    tap.diagnostic("Diff command: `{}`".format(" ".join(abidiff_command)))
    abidiff = subprocess.Popen(
        abidiff_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    output = ""
    while True:
        _outs, _errs = abidiff.communicate()
        output += _outs.decode("utf-8")
        if abidiff.returncode is not None:
            break

    message = "No ABI changes detected"
    success = True
    if abidiff.returncode & 8 == 8:
        success = False
        message = "Breaking ABI changes detected"
    elif abidiff.returncode & 4 == 4:
        message = "ABI changes changes detected"
    elif abidiff.returncode != 0:
        success = False
        message = "Error running abidiff, return code '{}'".format(abidiff.returncode)

    tap.diagnostic("ABI diff output:\n{}".format(output))
    tap.test(success, message)


tap = lttngtest.TapGenerator(1)
with lttngtest.test_environment(
    log=tap.diagnostic, with_relayd=False, with_sessiond=False
) as test_env:
    test_abi_diff(tap, test_env)

sys.exit(0 if tap.is_successful else 1)
