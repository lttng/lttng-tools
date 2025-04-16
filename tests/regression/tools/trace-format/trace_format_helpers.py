#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only

import pathlib
import os
import bt2
import subprocess
import json
import sys
import re
from typing import Callable

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest


def compare_text_files(actual_path, expect_path, tap):
    # type: (pathlib.Path, pathlib.Path, lttngtest.TapGenerator) -> None
    with open(actual_path, "r") as actual, open(expect_path, "r") as expected:
        actual_lines = actual.readlines()
        expected_lines = expected.readlines()

        if len(actual_lines) != len(expected_lines):
            missing_in_actual = set(expected_lines) - set(actual_lines)
            missing_in_expected = set(actual_lines) - set(expected_lines)

            if missing_in_actual:
                tap.diagnostic("Lines not found in actual file:")
                for line in missing_in_actual:
                    tap.diagnostic(f"- {line.rstrip()}")

            if missing_in_expected:
                tap.diagnostic("Extra lines in actual file:")
                for line in missing_in_expected:
                    tap.diagnostic(f"- {line.rstrip()}")

            raise AssertionError(
                f"Line count mismatch: got {len(actual_lines)} lines, expected {len(expected_lines)} lines"
            )

        for i, (actual_line, expected_line) in enumerate(
            zip(actual_lines, expected_lines)
        ):
            if actual_line != expected_line:
                tap.diagnostic(f"Difference at line {i+1}:")
                tap.diagnostic(f"Expected: {expected_line.rstrip()}")
                tap.diagnostic(f"Actual  : {actual_line.rstrip()}")

                # Highlight the specific difference
                for j, (a, e) in enumerate(zip(actual_line, expected_line)):
                    if a != e:
                        # Extract context around the difference (10 chars before and after)
                        start_pos = max(0, j - 10)
                        end_pos = min(len(actual_line), j + 10)
                        context = actual_line[start_pos:end_pos]
                        marker_pos = j - start_pos
                        pointer = " " * marker_pos + "^"

                        tap.diagnostic(
                            f"Differs at position {j}: [...{context.rstrip()}...]"
                        )
                        tap.diagnostic(f"{' ' * 16}{pointer}")
                        raise AssertionError("Content mismatch")


def get_metadata_directory(trace_path):
    # type: (pathlib.Path) -> pathlib.Path
    """
    Get the metadata directory from the trace path.

    This function walks the trace path and returns the first directory
    that contains a file named "metadata".
    """
    for root, dirs, files in os.walk(trace_path):
        if "metadata" in files:
            return pathlib.Path(root)
    raise FileNotFoundError(
        "Could not find 'metadata' file in the session output location hierarchy."
    )


def metadata_contents_from_local_output_location(trace_path):
    # type: (pathlib.Path) -> str
    ctf_fs_cc = bt2.find_plugin("ctf").source_component_classes["fs"]

    metadata_path = get_metadata_directory(trace_path)

    query_executor = bt2.QueryExecutor(
        ctf_fs_cc,
        "metadata-info",
        params={"path": str(metadata_path)},
    )

    return str(query_executor.query()["text"])


def check_ctf2_trace_smoketest(session_output_path, tap):
    # type: (pathlib.Path, lttngtest.TapGenerator) -> None
    metadata_contents = metadata_contents_from_local_output_location(
        session_output_path
    )

    metadata_fragments = []

    with tap.case("Load metadata fragments") as test_case:
        for fragment in metadata_contents.split("\x1e")[1:]:
            metadata_fragments.append(json.loads(fragment))

    with tap.case("Validate preamble fragment") as test_case:
        preamble = metadata_fragments[0]
        if "type" not in preamble:
            raise ValueError("Preamble fragment does not contain a 'type' property")
        if "uuid" not in preamble:
            raise ValueError("Preamble fragment does not contain a 'uuid' property")
        if "version" not in preamble:
            raise ValueError("Preamble fragment does not contain a 'version' property")
        if preamble["type"] != "preamble":
            raise ValueError("Preamble fragment has an unexpected 'type' property")
        if preamble["version"] != 2:
            raise ValueError(
                f"Preamble fragment has an unexpected 'version' property value ({preamble['version']})"
            )
        if len(preamble["uuid"]) != 16:
            raise ValueError(
                "Preamble fragment has an unexpected 'uuid' property length"
            )


def censor_section_lines(lines):
    # type: (list[str]) -> list[str]
    fields_to_ignore = {
        "product_uuid": "PRODUCT_UUID",
        "Offset from origin (s)": "OFFSET_FROM_ORIGIN_S",
        "Offset from origin (cycles)": "OFFSET_FROM_ORIGIN_CYCLES",
        "hostname": "HOSTNAME",
        "kernel_release": "KERNEL_RELEASE",
        "kernel_version": "KERNEL_VERSION",
        "trace_creation_datetime": "TRACE_CREATION_DATETIME",
        "trace_name": "TRACE_NAME",
        "tracer_major": "TRACER_MAJOR",
        "tracer_minor": "TRACER_MINOR",
        "tracer_patchlevel": "TRACER_PATCHLEVEL",
        "tracer_buffering_id": "TRACER_BUFFERING_ID",
    }

    censored_lines = []

    for line in lines:
        # Remove lines referencing padding fields as they are only needed
        # for the CTF 1.8 format.
        #
        # The CTF2 format does not require padding fields to be specified
        # since the spec allows a minimum alignment to be specified for
        # arrays/sequences.
        if "padding" in line:
            continue

        # Since padding fields may be removed, censor the number of members
        # in structures.
        line = re.sub(r"Structure \(\d+ members\)", "Structure (M members)", line)

        # The CTF 1.8 format does not have the concept of a clock "precision".
        if "Precision (cycles): " in line:
            continue

        # Some lines contain host-specific information that
        # must be censored to match the expected output
        # (e.g. kernel version, hostname, etc.)
        #
        # We replace the value with a constant string.
        for key, value in fields_to_ignore.items():
            match = re.match(rf"^(\s*){re.escape(key)}: ", line)
            if match:
                leading_space = match.group(1)
                line = re.sub(
                    rf"^(\s*){re.escape(key)}: .*",
                    f"{leading_space}{key}: {value}",
                    line,
                )
                break

        censored_lines.append(line)

    return censored_lines


def count_leading_spaces(string):
    # type (str) -> int
    count = 0
    for c in string:
        if c.isspace():
            count += 1
        else:
            break
    return count


def remove_user_attributes(section_lines):
    # type (list[str]) -> list[str]
    result_lines = []
    skip_until_indent = None

    for line in section_lines:
        # If we're in skip mode
        if skip_until_indent is not None:
            current_indent = len(line) - len(line.lstrip())

            # If reached a line with same or less indentation, exit skip mode
            if current_indent <= skip_until_indent:
                skip_until_indent = None
            else:
                # Skip this line
                continue

        # Check if this line starts a user attributes section
        if re.match(r"^\s*User attributes:", line):
            skip_until_indent = count_leading_spaces(line)
            # Skip this line
            continue

        # Add line to result if we're not skipping
        result_lines.append(line)

    return result_lines


def censor_section(section_lines):
    # type (list[str]) -> list[str]
    def is_event_section():
        return section_lines[1].strip().startswith("Event ")

    def is_stream_beginning_section():
        return section_lines[1].strip().startswith("Stream beginning:")

    def is_packet_beginning_section():
        return section_lines[1].strip().startswith("Packet beginning:")

    if section_lines[0].startswith("Trace class:"):
        # Remove user attributes as they don't exist in CTF 1.8.
        section_lines = remove_user_attributes(section_lines)
        return censor_section_lines(section_lines)

    # Validate the first line of the section and extract trace,
    # stream class and stream instance IDs.
    first_line = section_lines[0].strip()
    match = re.match(
        r"\{Trace (\d+), Stream class ID (\d+), Stream ID (\d+)\}",
        first_line,
    )
    if not match:
        raise AssertionError(f"Invalid section header format: {first_line}")

    trace_id, stream_class_id, stream_id = map(int, match.groups())
    if stream_id != 0 and not is_event_section():
        # Skip non-event messages that don't match stream 0
        # since the host running the test may not have the same
        # number of CPUs as the one used to generate the expected
        # output.
        return []

    # Censor the stream instance ID for event messages as it will vary
    # depending on the core that emitted the event.
    if is_event_section():
        section_lines[0] = (
            f"{{Trace {trace_id}, Stream class ID {stream_class_id}, Stream ID S}}\n"
        )
    elif is_stream_beginning_section():
        # Remove the declaration of stream instances that are not 0.
        new_section = section_lines[:2]
        for line in section_lines[2:]:
            match = re.match(r"^\s*Stream \(ID (\d+), Class ID \d+\)", line)
            if match and int(match.group(1)) != 0:
                continue
            new_section.append(line)
        section_lines = new_section
    elif is_packet_beginning_section():
        # Anonymize the cpu_id field
        new_section = section_lines[:2]
        for line in section_lines[2:]:
            if re.match(r"^\s*cpu_id: \d+", line):
                line = re.sub(r"cpu_id: \d+", "cpu_id: C", line)
            new_section.append(line)
        section_lines = new_section

    return censor_section_lines(section_lines)


def convert_trace_to_text_details(trace_path, text_output_file_path):
    # type: (pathlib.Path, pathlib.Path) -> None
    """
    This function uses Babeltrace to convert the trace to text format using
    the `sink.text.details` component.
    """
    trace_path = get_metadata_directory(trace_path)
    with open(text_output_file_path, "w") as f:
        process = subprocess.Popen(
            [
                "babeltrace2",
                "--component",
                "sink.text.details",
                "--params",
                "with-time=false,with-uid=false,with-uuid=false,with-trace-name=false,with-stream-name=false,color=never",
                str(trace_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        with process.stdout as stdout:
            # The output is consumed line by line while searching for the boundaries
            # of each section. Each section is processed and written to the output
            # file.
            current_section = []
            for line in stdout:
                if line.strip() != "":
                    # Still in a section, keep accumulating lines
                    current_section.append(line)
                    continue

                # We reached the end of a section, process it and write it to the output file
                current_section = censor_section(current_section)

                if len(current_section) > 0:
                    for line in current_section:
                        f.write(line)
                    f.write("\n")

                current_section.clear()

        process.wait()

    if process.returncode != 0:
        raise RuntimeError(
            f"Failed to convert trace to text details: {process.stderr.strip()}"
        )


def convert_trace_to_text_pretty(trace_path, text_output_file_path):
    # type: (pathlib.Path, pathlib.Path) -> None
    """
    This function uses Babeltrace to convert the trace to text format using
    the `sink.text.pretty` component.
    """
    trace_path = get_metadata_directory(trace_path)
    with open(text_output_file_path, "w") as f:
        process = subprocess.Popen(
            [
                "babeltrace2",
                "--component",
                "sink.text.pretty",
                "--params",
                "no-delta=true,field-trace:hostname=false,color=never",
                str(trace_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        with process.stdout as stdout:
            for line in stdout:
                line = line.replace(line[: line.find("]") + 1], "[TT:TT:TT.TTTTTTTTT]")
                line = re.sub(r"cpu_id = \d+", "cpu_id = C", line)
                line = re.sub(r"\w+_padding\s+=\s+\{\s+}(?:,\s+)?", "", line)
                f.write(line)
                f.flush()
        process.wait()
    if process.returncode != 0:
        raise RuntimeError(
            f"Failed to convert trace to text pretty: {process.stderr.strip()}"
        )


def check_trace_event_counts(session_output_path, expected_event_counts):
    # type: (pathlib.Path, dict[str, int]) -> None
    event_counts = {}
    for msg in bt2.TraceCollectionMessageIterator(str(session_output_path)):
        if type(msg) is not bt2._EventMessageConst:
            continue

        event_name = msg.event.name
        if event_name not in event_counts:
            event_counts[event_name] = 0
        event_counts[event_name] += 1

    mismatched_events = []
    for event_name, expected_count in expected_event_counts.items():
        actual_count = event_counts.get(event_name, 0)
        if actual_count != expected_count:
            mismatched_events.append(
                f"Event '{event_name}': expected {expected_count}, got {actual_count}"
            )

    for event_name, actual_count in event_counts.items():
        if event_name not in expected_event_counts:
            mismatched_events.append(
                f"Unexpected event '{event_name}': got {actual_count}"
            )

    if mismatched_events:
        raise AssertionError(
            "Event counts do not match:\n" + "\n".join(mismatched_events)
        )


def test_local_trace_all_formats(
    tap,
    capture_local_trace,
    pretty_expect_path,
    enable_kernel_domain,
    expected_events,
):
    # type: (lttngtest.TapGenerator, Callable[[lttngtest._Environment], pathlib.Path], pathlib.Path, bool, dict[str, int]) -> None
    with lttngtest.test_environment(with_sessiond=False) as text_trace_environment:
        ctf_1_8_text_folder = text_trace_environment.create_temporary_directory(
            "ctf 1.8"
        )
        ctf2_text_folder = text_trace_environment.create_temporary_directory("ctf")

        ctf2_pretty_path = ctf2_text_folder / "pretty.txt"
        ctf_1_8_pretty_path = ctf_1_8_text_folder / "pretty.txt"

        ctf2_details_path = ctf2_text_folder / "details.txt"
        ctf_1_8_details_path = ctf_1_8_text_folder / "details.txt"

        with lttngtest.test_environment(
            with_sessiond=True,
            log=tap.diagnostic,
            extra_env_vars={
                "LTTNG_EXPERIMENTAL_FORCE_CTF_2": "1",
            },
            enable_kernel_domain=enable_kernel_domain,
        ) as ctf2_test_env:
            output_path = None
            with tap.case("Capture a local trace in CTF2 format"):
                output_path = capture_local_trace(ctf2_test_env)

            check_ctf2_trace_smoketest(output_path, tap)
            with tap.case("Decode trace and count events by name"):
                check_trace_event_counts(output_path, expected_events)

            tap.diagnostic(
                'Converting CTF2 trace to "pretty" text format using Babeltrace'
            )
            convert_trace_to_text_pretty(output_path, ctf2_text_folder / "pretty.txt")

            tap.diagnostic(
                'Converting CTF2 trace to "details" text format using Babeltrace'
            )
            convert_trace_to_text_details(output_path, ctf2_text_folder / "details.txt")

        with lttngtest.test_environment(
            with_sessiond=True,
            log=tap.diagnostic,
            enable_kernel_domain=enable_kernel_domain,
        ) as ctf_1_8_test_env:
            output_path = None
            with tap.case("Capture a local trace in CTF 1.8 format"):
                output_path = capture_local_trace(ctf_1_8_test_env)

            with tap.case("Decode trace and count events by name"):
                check_trace_event_counts(output_path, expected_events)

            tap.diagnostic(
                'Converting CTF 1.8 trace to "pretty" text format using Babeltrace'
            )
            convert_trace_to_text_pretty(
                output_path, ctf_1_8_text_folder / "pretty.txt"
            )

            tap.diagnostic(
                'Converting CTF 1.8 trace to "details" text format using Babeltrace'
            )
            convert_trace_to_text_details(
                output_path, ctf_1_8_text_folder / "details.txt"
            )

        with tap.case("Compare CTF 1.8 pretty output with CTF2 pretty output"):
            compare_text_files(ctf_1_8_pretty_path, ctf2_pretty_path, tap)

        with tap.case("Compare CTF2 pretty output with expected output"):
            compare_text_files(ctf2_pretty_path, pretty_expect_path, tap)

        with tap.case("Compare CTF 1.8 pretty output with expected output"):
            compare_text_files(ctf_1_8_pretty_path, pretty_expect_path, tap)

        with tap.case("Compare CTF 1.8 details output with CTF2 details output"):
            compare_text_files(ctf_1_8_details_path, ctf2_details_path, tap)
