# SPDX-FileCopyrightText: 2025 Olivier Dion <odion@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only

import contextlib
import mmap
import os
import pathlib
import shutil
import signal
import subprocess

import bt2

gdb_helper_script_path = pathlib.Path(__file__).absolute().parents[0] / "gdb_helper.py"


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
            self.scheduling = scheduling or []
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

            gdb_script_path = str(
                test_env.create_temporary_directory("gdb_script_dir") / "gdb_script"
            )

            applications = [
                stack.enter_context(self.traced_application(test_env))
                for producer in self.producers
            ]

            # Build GDB script content
            gdb_commands = []

            # Basic GDB settings
            gdb_commands.extend(
                [
                    "set trace-commands on",
                    "set breakpoint pending on",
                    "set pagination off",
                    "set auto-load off",
                    "handle SIGTRAP stop noprint nopass",
                    "handle SIGSTOP stop noprint nopass",
                    "source {}".format(gdb_helper_script_path),
                ]
            )

            # Set debug file directory if specified
            gdb_debug_directory = os.getenv("GDB_DEBUG_FILE_DIRECTORY")
            if gdb_debug_directory:
                gdb_commands.append(
                    "set debug-file-directory {}".format(gdb_debug_directory)
                )

            # Add inferiors to match number of applications
            for k in range(len(applications) - 1):
                gdb_commands.append("add-inferior")

            # Attach to each application
            k = 0
            producer_to_inferior = {}
            for producer in self.producers:
                producer_to_inferior[producer] = k + 1
                gdb_commands.extend(
                    [
                        "inferior {}".format(k + 1),
                        "attach {}".format(applications[k].vpid),
                    ]
                )
                k += 1

            # Touch tracing files to start tracing loops
            for application in applications:
                gdb_commands.append(
                    "shell touch {}".format(application.start_tracing_path)
                )

            # Execute scheduling
            for schedule in self.scheduling:
                producer = schedule[0]
                testpoint = schedule[1]

                gdb_commands.extend(
                    [
                        "inferior {}".format(producer_to_inferior[producer]),
                        "python break_testpoint('lttng_ust_testpoint_{}')".format(
                            testpoint
                        ),
                    ]
                )

                # Handle scenarios that might be impossible
                if self.might_be_impossible:
                    gdb_commands.append("break exit")

                gdb_commands.extend(
                    [
                        "continue",
                        "delete",
                    ]
                )

            # Kill all applications
            gdb_commands.append(
                "kill inferiors {}".format(
                    " ".join([str(k + 1) for k in range(len(applications))])
                )
            )

            # Write GDB script to file
            with open(gdb_script_path, "w") as f:
                for cmd in gdb_commands:
                    f.write("shell date\n")
                    f.write(cmd + "\n")
                    f.write("shell date\n")

            # Execute GDB with the script
            gdb_args = [
                "gdb",
                "--nx",  # No loading of any .gdbinit
                "--nw",  # No GUI
                "--batch",  # Exit when all commands are executed
                "-x",
                gdb_script_path,  # Execute script
            ]

            with subprocess.Popen(
                gdb_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            ) as process:
                try:
                    output, _ = process.communicate(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()

                    output, _ = process.communicate()
                    for line in output.decode("utf-8", errors="ignore").splitlines():
                        log("GDB (timeout): {}".format(line))

                    # Re-raise the exception so the test fails.
                    raise

            output = output.decode("utf-8")

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
                self.discarded_events
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


# Dump the contents of a trace to the TAP log.
def dump_trace_contents(trace_path, tap):
    try:
        result = subprocess.run(
            ["babeltrace2", "--component", "sink.text.details", str(trace_path)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        for line in result.stdout.splitlines():
            tap.diagnostic(line.decode("utf-8"))
    except subprocess.CalledProcessError as ex:
        tap.diagnostic("Failed to dump trace contents: {}".format(ex))
