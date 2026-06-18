#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Effective value type (counter bitness) of *kernel* map channels in mixed-bitness
environments.

The effective value type of a map channel's counters depends on three
independent variables:

  1. the session daemon's bitness (32 or 64);
  2. the kernel's bitness (32 or 64);
  3. the configured value type: `signed-int-32`, `signed-int-64`, or
     `signed-int-max` (follow the ABI).

A host can't store a counter wider than itself, so some combinations must fail at
creation. For a created channel, the counter is driven to a known value through
the `lttng-test` kernel module (an "increment map value" trigger on
`lttng_test_filter_event`, then a write to /proc/lttng-test-filter-event) and
read back with `export-maps`; the map group's `value_type` column is the
effective value type (see lttng-export-maps(1)).

The session daemon does not detect the running kernel's bitness; it assumes the
kernel shares its own. So a 32-bit daemon on a 64-bit kernel runs fine but
behaves as it would on a 32-bit kernel: it creates 32-bit and Max (resolved to
32-bit) maps, and rejects a 64-bit map (KERN-05) even though the 64-bit kernel
could host one. Those rows run like the rest; they assert that current behavior.
"""

import logging
import pathlib
import platform
import sys
from typing import Optional

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common

from map_value_type_multilib_utils import (
    COUNTER_KEY,
    EVENT_COUNT,
    Case,
    profile_for_word_size,
    read_counter,
)

# Aliases to keep the CASES table below readable.
_Domain = lttngtest.lttngctl.TracingDomain
_ValueType = lttngtest.MapChannelValueType


def host_kernel_word_size_bits() -> Optional[int]:
    """
    Word size of the running kernel, or None when it can't be determined.

    A 64-bit kernel reports a 64-bit machine even when userspace is 32-bit, so
    the kernel's own word size is read from `uname` rather than the
    interpreter's pointer size.
    """
    machine = platform.machine().lower()
    bits64 = {
        "x86_64",
        "amd64",
        "aarch64",
        "arm64",
        "ppc64",
        "ppc64le",
        "s390x",
        "riscv64",
        "mips64",
        "loongarch64",
        "sparc64",
        "ia64",
    }
    bits32 = {
        "i386",
        "i486",
        "i586",
        "i686",
        "x86",
        "arm",
        "armv6l",
        "armv7l",
        "ppc",
        "s390",
        "mips",
        "riscv32",
    }
    if machine in bits64:
        return 64
    if machine in bits32:
        return 32
    return None


# The kernel bitness matrix. Each row is one tracing session: a kernel map
# channel of the "Configured" value type is created on a "Sessiond"-bit session
# daemon; the peer is the running "Kernel". "Created" is the expected creation
# outcome; for a created channel, "Effective" is the resolved counter width,
# verified by driving the counter and reading its vmap `value_type` back. A dash
# means the channel is never created.
#
#   ID       Sessiond  Kernel  Configured  Created  Effective
#   KERN-01  32        32      32           yes      32
#   KERN-02  32        32      64           no       -
#   KERN-03  32        32      Max          yes      32
#   KERN-04  32        64      32           yes      32
#   KERN-05  32        64      64           no       -
#   KERN-06  32        64      Max          yes      32
#   KERN-07  64        64      32           yes      32
#   KERN-08  64        64      64           yes      64
#   KERN-09  64        64      Max          yes      64
#
# KERN-04..06 run a 32-bit daemon on a 64-bit kernel. The daemon assumes the
# kernel shares its 32-bit bitness, so it behaves as the 32-bit-kernel rows
# above: 32-bit and Max (resolved to 32-bit) maps are created, and a 64-bit map
# is rejected (KERN-05) even though the 64-bit kernel could host it.
CASES = [
    Case("KERN-01", _Domain.Kernel, 32, 32, _ValueType.SignedInt32, True, 32),
    Case("KERN-02", _Domain.Kernel, 32, 32, _ValueType.SignedInt64, False),
    Case("KERN-03", _Domain.Kernel, 32, 32, _ValueType.SignedIntMax, True, 32),
    Case("KERN-04", _Domain.Kernel, 32, 64, _ValueType.SignedInt32, True, 32),
    Case("KERN-05", _Domain.Kernel, 32, 64, _ValueType.SignedInt64, False),
    Case("KERN-06", _Domain.Kernel, 32, 64, _ValueType.SignedIntMax, True, 32),
    Case("KERN-07", _Domain.Kernel, 64, 64, _ValueType.SignedInt32, True, 32),
    Case("KERN-08", _Domain.Kernel, 64, 64, _ValueType.SignedInt64, True, 64),
    Case("KERN-09", _Domain.Kernel, 64, 64, _ValueType.SignedIntMax, True, 64),
]


def drive_kernel_counter(
    client: lttngtest.LTTngClient,
    session: lttngtest.Session,
    channel: lttngtest.KernelMapChannel,
) -> None:
    """
    Register an "increment map value" trigger on `lttng_test_filter_event`, start
    the session, then ask the (already loaded) `lttng-test` module to emit
    EVENT_COUNT such events. Each matching event increments the channel's counter.
    """
    # The event-rule-matches condition enables the kernel event, so the trigger
    # must exist before the events are emitted.
    client.add_trigger(
        lttngtest.EventRuleMatchesCondition(
            lttngtest.KernelTracepointEventRule("lttng_test_filter_event")
        ),
        [
            lttngtest.IncrementMapValueTriggerAction(
                session.name, channel.name, lttngtest.KernelMapChannel, COUNTER_KEY
            )
        ],
    )

    session.start()
    common.fire_kernel_test_events(EVENT_COUNT)


def run_kernel_case(
    tap: lttngtest.TapGenerator, case: Case, host_kernel_bits: Optional[int]
) -> None:
    if not lttngtest._Environment.run_kernel_tests():
        tap.skip(
            "{}: kernel cases require root and an unset "
            "LTTNG_TOOLS_DISABLE_KERNEL_TESTS".format(case.description)
        )
        return

    if host_kernel_bits is None:
        tap.skip(
            "{}: host kernel word size could not be determined".format(case.description)
        )
        return

    if case.peer_bits != host_kernel_bits:
        tap.skip(
            "{}: needs a {}-bit kernel, host kernel is {}-bit".format(
                case.description, case.peer_bits, host_kernel_bits
            )
        )
        return

    sessiond_profile = profile_for_word_size(case.sessiond_bits)
    if sessiond_profile is None:
        tap.skip(
            "{}: no {}-bit build profile available".format(
                case.description, case.sessiond_bits
            )
        )
        return

    try:
        with (
            lttngtest.kernel_module("lttng-test"),
            lttngtest.test_environment(
                with_sessiond=True,
                log=tap.diagnostic,
                enable_kernel_domain=True,
                sessiond_profile=sessiond_profile,
                client_profile=sessiond_profile,
                consumerd_profiles=[sessiond_profile],
            ) as test_env,
        ):
            client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
            session = client.create_session(
                output=lttngtest.LocalSessionOutputLocation(
                    test_env.create_temporary_directory("trace")
                )
            )

            created = True
            channel = None
            try:
                channel = session.add_kernel_map_channel(value_type=case.configured)
            except lttngtest.LTTngClientError:
                created = False

            if created != case.created:
                tap.fail(
                    "{}: expected created={}, got {}".format(
                        case.description, case.created, created
                    )
                )
                return

            if not case.created:
                tap.ok("{}: rejected at creation as expected".format(case.name))
                return

            # Reaching here implies a successful creation above.
            assert channel is not None
            drive_kernel_counter(client, session, channel)

            # The group whose value type equals the effective width must exist
            # and have counted every event: this confirms the effective type.
            total, entries = read_counter(
                session, channel.name, COUNTER_KEY, case.effective
            )
            tap.test(
                entries > 0 and total == EVENT_COUNT,
                "{}: counter has effective {}-bit value type "
                "(total={}, expected={})".format(
                    case.name, case.effective, total, EVENT_COUNT
                ),
            )

            session.stop()
            session.destroy()
    except Exception as case_error:
        logging.exception("Unhandled exception during case %s", case.name)
        tap.fail("{}: {}".format(case.description, case_error))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format=lttngtest.utils.get_logging_format())

    host_kernel_bits = host_kernel_word_size_bits()

    # One test case per row; cases whose required kernel bitness, word size, or
    # privilege is unavailable (or whose daemon/kernel bitness differ) are
    # reported as skips within the plan.
    tap = lttngtest.TapGenerator(len(CASES))

    for case in CASES:
        run_kernel_case(tap, case, host_kernel_bits)

    sys.exit(0 if tap.is_successful else 1)
