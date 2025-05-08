# SPDX-FileCopyrightText: 2025 Olivier Dion <odion@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only

import contextlib
import mmap
import os
import shutil
import signal
import subprocess

import bt2


class StallScenario:
    """
    A stall scenario is a list of testpoints and some optional expectations
    and parameters.

    Each testpoint is associated with a different producer. All producers will
    be stopped once they reach their corresponding testpoint. Once all producers
    are in place, they are all killed. The resulting trace is analyzed and
    compared against the scenario's expectations.
    """

    def __init__(
        self,
        testpoints=None,
        synopsis=None,
        producers=None,
        scheduling=None,
        expected_events=None,
        expected_discarded_events=None,
        expected_packets=None,
        expected_discarded_packets=None,
        subbuf_size=mmap.PAGESIZE,
        subbuf_count=8,
        might_be_impossible=False,
    ):
        if producers:
            self.producers = producers
            self.scheduling = scheduling
        elif testpoints:
            self.producers = [k for k in range(len(testpoints))]
            self.scheduling = [(k, testpoints[k]) for k in range(len(testpoints))]
        else:
            self.producers = []
            self.scheduling = []

        self.synopsis = synopsis or " ".join(testpoints)
        self.expected_events = self.make_expectation(expected_events)
        self.expected_discarded_events = self.make_expectation(
            expected_discarded_events
        )
        self.expected_packets = self.make_expectation(expected_packets)
        self.expected_discarded_packets = self.make_expectation(
            expected_discarded_packets
        )
        self.buf_size = subbuf_size * subbuf_count
        self.subbuf_size = subbuf_size
        self.subbuf_count = subbuf_count
        self.might_be_impossible = might_be_impossible

    # An expectation is a producer accepting a single argument, returning True
    # if that argument pass the expectation.
    @staticmethod
    def make_expectation(expected):

        # If None, always return True for this expectation.
        if expected is None:
            return lambda x: True

        if callable(expected):
            return expected

        # Argument must match the expectation.
        return lambda x: x == expected

    @contextlib.contextmanager
    def traced_application(self, test_env):

        app = test_env.launch_wait_trace_test_application(self.buf_size)

        yield app

        # It is expected for all traced applications to be killed with SIGKILL
        # by GDB.
        #
        # If the application exits gracefully, this is an error of the test.
        #
        # If the application exits with a status different than SIGKILL, then
        # there is a bug somewhere.
        try:
            app.wait_for_exit()
            raise Exception("Process was not killed by GDB")
        except RuntimeError as exn:
            status = app.status

            if status and status < 0 and status == -signal.SIGKILL:
                pass
            else:
                raise exn

    def __call__(self, log, test_env, session):
        with contextlib.ExitStack() as stack:

            applications = [
                stack.enter_context(self.traced_application(test_env))
                for producer in self.producers
            ]

            gdb_args = [
                "gdb",
                "--nx",  # No loading of any .gdbinit
                "--nw",  # No GUI
                "--batch",  # Exit when all commands are executed
                "-ex",
                "set trace-commands on",  # Print all command invocations
                "-ex",
                "set breakpoint pending on",  # Do not prompt for breakpoint insertion
                "-ex",
                "set pagination off",  # Do not prompt for more output
                "-ex",
                "set auto-load off",  # Do not auto-load script files
                "-ex",
                "handle all nostop noprint pass",  # Do not hide failed assertions
            ]

            # Set this environment variable if debug-symbols for LTTng-UST are
            # not in a standard location or in a different file than the
            # shared-library (.debug_link).
            gdb_debug_directory = os.getenv("GDB_DEBUG_FILE_DIRECTORY")
            if gdb_debug_directory:
                gdb_args.extend(
                    ["-ex", "set debug-file-directory {}".format(gdb_debug_directory)]
                )

            # If the scenario may be impossible to produced, one of the producer
            # will exit gracefully, resulting in a failure of the test.
            #
            # To ensure that all producers are killed by GDB, set a breakpoint
            # on the exit symbol.
            #
            # However, some scenarios are known to be possible to happen and so
            # this is why this an option.
            #
            # See test_stall_buffer_complex.py for complete rationale.
            if self.might_be_impossible:
                gdb_args.extend(["-ex", "break exit"])

            # By default, GDB starts with a single inferior.
            #
            # Add more to match the number of application.
            for k in range(len(applications) - 1):
                gdb_args.extend(["-ex", "add-inferior"])

            # For each application, attach to a matching inferior process.
            k = 0
            producer_to_inferior = {}
            for producer in self.producers:
                producer_to_inferior[producer] = k + 1
                gdb_args.extend(
                    [
                        "-ex",
                        "inferior {}".format(k + 1),
                        "-ex",
                        "attach {}".format(applications[k].vpid),
                    ]
                )
                k += 1

            # At this point, all producers are stopped after being attached.
            #
            # For each application, touch the special tracing file so that all
            # producers will start their tracing loop after continuing.
            for application in applications:
                gdb_args.extend(
                    [
                        "-ex",
                        "shell touch {}".format(application.start_tracing_path),
                    ]
                )

            # Emit the scheduling.
            for schedule in self.scheduling:

                producer = schedule[0]
                testpoint = schedule[1]

                gdb_args.extend(
                    [
                        "-ex",
                        "inferior {}".format(producer_to_inferior[producer]),
                        "-ex",
                        "tbreak lttng_ust_testpoint_{}".format(testpoint),
                        "-ex",
                        "continue",
                    ]
                )

            # At this point, all producers are at their corresponding final
            # testpoints (or in exit(3)). Kill all applications to see what
            # happens.
            gdb_args.extend(
                [
                    "-ex",
                    "kill inferiors {}".format(
                        " ".join([str(k + 1) for k in range(len(applications))])
                    ),
                ]
            )

            output = subprocess.check_output(
                gdb_args, timeout=5, stderr=subprocess.STDOUT
            ).decode("utf-8")

            # Just emit the output of GDB with TAP for better error reporting.
            for line in output.splitlines():
                log("GDB: {}".format(line))


class TraceStats:
    """
    A trace statistic is four counters:

    - Number of events

    - Number of discarded events

    - Number of packets

    - Number of discarded packets

    """

    def __init__(self, trace_location):

        ignore_set = {
            bt2._StreamBeginningMessageConst,
            bt2._StreamEndMessageConst,
            bt2._PacketEndMessageConst,
        }

        events = 0
        discarded_events = 0
        packets = 0
        discarded_packets = 0
        for msg in bt2.TraceCollectionMessageIterator(trace_location):
            if type(msg) is bt2._EventMessageConst:
                events += 1
            elif type(msg) is bt2._DiscardedEventsMessageConst:
                discarded_events += msg.count or 1
            elif type(msg) is bt2._PacketBeginningMessageConst:
                packets += 1
            elif type(msg) is bt2._DiscardedPacketsMessageConst:
                discarded_packets += msg.count or 1
            elif type(msg) in ignore_set:
                pass
            else:
                raise Exception("Unexpected message type: {}".format(type(msg)))

        self.events = events
        self.discarded_events = discarded_events
        self.packets = packets
        self.discarded_packets = discarded_packets

    def unmet_scenario_expectations(self, scenario):
        """Check that these statistics met the expectations of `scenario`.

        Return None if all expecations were met. Otherwise, return an error
        string.

        """
        if not scenario.expected_events(self.events):
            return "Events count `{}` does not match scenario expectation".format(
                self.events
            )

        if not scenario.expected_discarded_events(self.discarded_events):
            return "Events discarded count `{}` does not match scenario expectation".format(
                stats.discarded_events
            )

        if not scenario.expected_packets(self.packets):
            return "Packets count `{}` does not match scenario expectation".format(
                self.packets
            )

        if not scenario.expected_discarded_packets(self.discarded_packets):
            return "Packets discarded count `{}` does not match scenario expectation".format(
                self.discarded_packets
            )

        return None


def validate_trace(trace_location):
    """Validate that the trace at location `trace_location` is a valid trace.

    This is done by running the following bt2 graph on the trace:

    trace_location -> [source:ctf:fs] -> [filter:utils:muxer] ->
    [sink:utils:dummy]

    """

    inputs = []
    for dirpath, dirs, files in os.walk(trace_location):
        if "metadata" in files:
            inputs.append(dirpath)

    ctf = bt2.find_plugin("ctf")
    assert ctf

    fs = ctf.source_component_classes["fs"]
    assert fs

    utils = bt2.find_plugin("utils")
    assert utils

    dummy = utils.sink_component_classes["dummy"]
    assert dummy

    muxer = utils.filter_component_classes["muxer"]
    assert muxer

    graph = bt2.Graph()

    src = graph.add_component(fs, "source", params={"inputs": inputs})
    mux = graph.add_component(muxer, "filter")
    sink = graph.add_component(dummy, "sink")

    for src_name in tuple(src.output_ports):
        graph.connect_ports(
            src.output_ports[src_name], tuple(mux.input_ports.values())[-1]
        )

    graph.connect_ports(mux.output_ports["out"], sink.input_ports["in"])

    graph.run()


def gdb_exists():
    """Return true if GDB can be executed."""
    return shutil.which("gdb") is not None
