#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Jérémie Galarneau <jeremie.galarneau@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Validates that combining metadata regeneration and session rotations works as
expected. Regenerating metadata and rotating the session in quick succession
should not result in corrupted metadata.

This essentially validates the synchronization between the metadata extraction
and rotation mechanisms to ensure a rotation only completes once the metadata
has been fully extracted.
"""

import os
import pathlib
import shutil
import sys
import subprocess
import tempfile

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest


def test_regenerate_rotate_local_ust(
    tap, test_env, output_path, iterations=5, chunks_before_validation=5
):
    session_output_location = lttngtest.LocalSessionOutputLocation(
        pathlib.Path(output_path)
    )

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(output=session_output_location)
    channel = session.add_channel(lttngtest.lttngctl.TracingDomain.User)
    channel.add_recording_rule(
        lttngtest.lttngctl.UserTracepointEventRule("many_events*")
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()

    # This app is run once so that the metadata for the session's streams is
    # relatively large (~0.9MiB). When combined with a delayed write device,
    # the races between rotate and regenerate happen more frequently.
    multi_event_app = test_env.launch_multi_event_wait_trace_test_application(1)
    multi_event_app.trace()
    multi_event_app.wait_for_exit()

    # Perform metadata regeneration and rotation in quick succession
    paths_to_read = []
    fail_count = 0
    for iteration in range(iterations):
        app = test_env.launch_wait_trace_test_application(100)
        app.trace()
        session.regenerate(lttngtest.SessionRegenerateTarget.Metadata)
        session.rotate()
        app.wait_for_exit()

        # Under the path session.output.path/archives, find the path that contains the
        # youngest metadata file
        metadata_files = list(
            pathlib.Path(session.output.path / "archives").rglob("metadata")
        )
        youngest_metadata = max(metadata_files, key=lambda p: p.stat().st_mtime)
        youngest_metadata_dir = youngest_metadata.parent
        paths_to_read.append(youngest_metadata_dir)

        if (
            len(paths_to_read) == chunks_before_validation
            or iteration == iterations - 1
        ):
            fail_count += validate_paths(tap, paths_to_read, "failed_trace_ust_")
            paths_to_read = list()

    # Stop session
    session.stop()

    # Validate trace
    session.destroy()

    tap.test(
        fail_count == 0,
        "{} failure(s) over {} iterations of regen + rotate with UST tracer".format(
            fail_count, iterations
        ),
    )


def test_regenerate_rotate_local_kernel(
    tap, test_env, output_path, iterations=5, chunks_before_validation=5
):
    session_output_location = lttngtest.LocalSessionOutputLocation(
        pathlib.Path(output_path)
    )

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(output=session_output_location)
    channel = session.add_channel(lttngtest.lttngctl.TracingDomain.Kernel)
    # The CTF 1.8 metadata with all events and the lttng-test module loaded is about 3.6M
    channel.add_recording_rule(lttngtest.lttngctl.KernelTracepointEventRule("*"))

    session.start()

    # Perform metadata regeneration and rotation in quick succession
    paths_to_read = []
    fail_count = 0
    for iteration in range(iterations):
        with open("/proc/lttng-test-filter-event", "w") as f:
            f.write("100")

        session.regenerate(lttngtest.SessionRegenerateTarget.Metadata)
        session.rotate()

        # Under the path session.output.path/archives, find the path that contains the
        # youngest metadata file
        metadata_files = list(
            pathlib.Path(session.output.path / "archives").rglob("metadata")
        )
        youngest_metadata = max(metadata_files, key=lambda p: p.stat().st_mtime)
        youngest_metadata_dir = youngest_metadata.parent
        paths_to_read.append(youngest_metadata_dir)

        if (
            len(paths_to_read) == chunks_before_validation
            or iteration == iterations - 1
        ):
            fail_count += validate_paths(tap, paths_to_read, "failed_trace_kernel_")
            paths_to_read = []

    # Stop session
    session.stop()
    session.destroy()
    tap.test(
        fail_count == 0,
        "{} failure(s) over {} iterations of regen + rotate with kernel tracer".format(
            fail_count, iterations
        ),
    )


def validate_paths(tap, paths, prefix=""):
    fail_count = 0
    tap.diagnostic("Validating events for {} metadata directories".format(len(paths)))
    for path in paths:
        try:
            received, discarded = lttngtest.count_events(path)
            tap.diagnostic("  Path {}: received {} events".format(path, received))
        except Exception as e:
            fail_count += 1
            tap.diagnostic("  Validation failed for path {}: {}".format(path, e))
            # Preserve this trace if required by LTTNG_TEST_PRESERVE_TEST_ENV
            # or LTTNG_TEST_PRESERVE_TEST_ENV_ON_FAILURE, since it's on a
            # storage that will be cleaned up during teardown.
            #
            # Copying to a TemporaryDirectory allows the harness to
            # automatically preserve it based on the environment variables.
            saved_trace_dir = lttngtest.TemporaryDirectory(prefix)

            shutil.rmtree(saved_trace_dir.path)
            shutil.copytree(path, saved_trace_dir.path)
            tap.diagnostic("Copied failed trace to: `{}`".format(saved_trace_dir.path))

            # Delete chunks after validation
            shutil.rmtree(path)
    return fail_count


def check_requirements(tap):
    if os.getuid() != 0:
        tap.missing_platform_requirement("Must run as root")

    if not lttngtest._Environment.allows_destructive():
        tap.missing_platform_requirement(
            "LTTNG_ENABLE_DESTRUCTIVE_TESTS must be set to 'will-break-my-system'"
        )

    required_binaries = [
        "truncate",
        "losetup",
        "mkfs.ext4",
        "dmsetup",
        "mount",
        "umount",
        "blockdev",
    ]
    for binary in required_binaries:
        if not shutil.which(binary):
            tap.missing_platform_requirement(
                "Missing required binary `{}`".format(binary)
            )


class SetupException(Exception):
    def __init__(self, teardown_commands, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.teardown_commands = teardown_commands


def setup(tap):
    teardown_commands = list()
    try:
        # Create a tempfile
        fd, temp = tempfile.mkstemp()
        teardown_commands.append(["rm", temp])
        tap.diagnostic("Created tempfile `{}`".format(temp))
        os.close(fd)

        # Truncate to 1GiB
        p = subprocess.Popen(["truncate", "-s", "1G", temp])
        p.wait()
        if p.returncode != 0:
            raise Exception(
                "Failed to truncate tempfile `{}`: ret=`{}`".format(temp, p.returncode)
            )

        tap.diagnostic("Resized tempfile `{}` to 1G".format(temp))
        # Create a loopback device
        p = subprocess.Popen(
            ["losetup", "--show", "-f", temp],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        p.wait()
        if p.returncode != 0:
            raise Exception(
                "Failed to create loopback device: ret=`{}`".format(p.returncode)
            )

        loopback_device = p.stdout.read().decode("utf-8").splitlines()[0]
        tap.diagnostic("Created loopback device `{}`".format(loopback_device))
        teardown_commands.append(["losetup", "-d", loopback_device])

        # Format loop device
        p = subprocess.Popen(["mkfs.ext4", loopback_device])
        p.wait()
        if p.returncode != 0:
            raise Exception(
                "Failed to format loopback device `{}` as ext4: ret=`{}`".format(
                    loopback_device, p.returncode
                )
            )

        # Create a delayed device
        p = subprocess.Popen(
            ["blockdev", "--getsz", loopback_device], stdout=subprocess.PIPE
        )
        p.wait()
        if p.returncode != 0:
            raise Exception(
                "Failed to get device size of `{}`: ret=`{}`".format(
                    loopback_device, p.returncode
                )
            )

        device_size = p.stdout.read().decode("utf-8").splitlines()[0]
        dm_device_name = "delayed"
        p = subprocess.Popen(
            [
                "dmsetup",
                "create",
                dm_device_name,
                "--table",
                # 0ms read delay, 10ms write delay, 0ms flush delay
                "0 {} delay {} 0 0 {} 0 10 {} 0 0".format(
                    device_size, loopback_device, loopback_device, loopback_device
                ),
            ]
        )
        p.wait()
        if p.returncode != 0:
            raise Exception(
                "Failed to create delayed device: ret=`{}`".format(p.returncode)
            )

        dm_device_path = "/dev/mapper/{}".format(dm_device_name)
        tap.diagnostic("Created delayed dm device `{}`".format(dm_device_path))
        teardown_commands.append(["dmsetup", "remove", dm_device_path])

        # Create a mount point
        mount_point = tempfile.mkdtemp()
        tap.diagnostic("Created temporary mount directory `{}`".format(mount_point))
        teardown_commands.append(["rm", "-rf", mount_point])

        # Mount delayed device
        p = subprocess.Popen(["mount", dm_device_path, mount_point])
        p.wait()
        if p.returncode != 0:
            raise Exception(
                "Failed to mount `{}` to `{}`: ret=`{}`".format(
                    dm_device_path, mount_point, p.returncode
                )
            )
        tap.diagnostic("Mounted `{}` to `{}`".format(dm_device_path, mount_point))
        teardown_commands.append(["umount", mount_point])

    except Exception as e:
        raise SetupException(
            teardown_commands, "Exception during setup: {}".format(str(e))
        )

    return mount_point, teardown_commands


def teardown(tap, commands):
    for command in reversed(commands):
        tap.diagnostic("Running teardown command: {}".format(command))
        p = subprocess.Popen(command)
        p.wait()
        if p.returncode != 0:
            tap.diagnostic(
                "Failed to run teardown command, ret=`{}`".format(p.returncode)
            )


if __name__ == "__main__":
    tap = lttngtest.TapGenerator(2)
    check_requirements(tap)
    try:
        output_path, teardown_commands = setup(tap)
    except SetupException as e:
        teardown(tap, e.teardown_commands)
        raise e

    try:
        with lttngtest.test_environment(
            with_sessiond=True, log=tap.diagnostic
        ) as test_env:
            test_regenerate_rotate_local_ust(tap, test_env, output_path)

        with lttngtest.test_environment(
            with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=True
        ) as test_env:
            with lttngtest.kernel_module("lttng-test"):
                test_regenerate_rotate_local_kernel(tap, test_env, output_path)
    finally:
        teardown(tap, teardown_commands)

    sys.exit(0 if tap.is_successful else 1)
