#!/usr/bin/env python3
#
# Copyright (C) - 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License, version 2 only, as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import os
import subprocess
import re
import shutil
import sys

test_path = os.path.dirname(os.path.abspath(__file__)) + "/"
test_utils_path = test_path
for i in range(4):
    test_utils_path = os.path.dirname(test_utils_path)
test_utils_path = test_utils_path + "/utils"
sys.path.append(test_utils_path)
from test_utils import *


def check_ust_test_demo2_event(event_line, expected_int_field_value):
    match = re.search(r".*ust_tests_demo2:loop.*", event_line)
    if match is None:
        return False
    match = re.search(r".*intfield = (\d+)", event_line)
    if match is None or int(match.group(1)) != expected_int_field_value:
        return False
    match = re.search(r".*longfield = (\d+)", event_line)
    if match is None or int(match.group(1)) != expected_int_field_value:
        return False
    match = re.search(r".*netintfield = (\d+)", event_line)
    if match is None or int(match.group(1)) != expected_int_field_value:
        return False
    match = re.search(r".*intfield2 = 0x(\d+)", event_line)
    if match is None or int(match.group(1)) != expected_int_field_value:
        return False
    match = re.search(r".*netintfieldhex = 0x(\d+)", event_line)
    if match is None or int(match.group(1)) != expected_int_field_value:
        return False
    match = re.search(r".*floatfield = (\d+)", event_line)
    if match is None or int(match.group(1)) != 2222:
        return False
    match = re.search(r".*doublefield = (\d+)", event_line)
    if match is None or int(match.group(1)) != 2:
        return False
    match = re.search(r".*_seqfield1_length = (\d+)", event_line)
    if match is None or int(match.group(1)) != 4:
        return False
    match = re.search(r".*seqfield1 = \[ \[0\] = (\d+), \[1\] = (\d+), \[2\] = (\d+), \[3\] = (\d+) \]", event_line)
    if match is None or int(match.group(1)) != 116 or int(match.group(2)) != 101 or int(match.group(3)) != 115 or int(match.group(4)) != 116:
        return False
    match = re.search(r".*arrfield1 = \[ \[0\] = (\d), \[1\] = (\d), \[2\] = (\d) \]", event_line)
    if match is None or int(match.group(1)) != 1 or int(match.group(2)) != 2 or int(match.group(3)) != 3:
        return False
    match = re.search(r".*arrfield2 = \"([a-z]*)\"", event_line)
    if match is None or match.group(1) != "test":
        return False
    match = re.search(r".*_seqfield2_length = (\d+)", event_line)
    if match is None or int(match.group(1)) != 4:
        return False
    match = re.search(r".*seqfield2 = \"([a-z]*)\"", event_line)
    if match is None or match.group(1) != "test":
        return False
    match = re.search(r".*stringfield = \"([a-z]*)\"", event_line)
    if match is None or match.group(1) != "test":
        return False

    return True

NR_TESTS = 0
DYNAMIC_TEST_ENABLED = False

test_executables = [test_path + "demo_static", test_path + "demo_builtin"]
if os.path.exists(test_path + "demo"):
    test_executables.append(test_path + "demo_preload")
    NR_TESTS = 2
    DYNAMIC_TEST_ENABLED = True

# Only enable tests that were compiled successfully
test_executables = [executable for executable in test_executables if os.path.exists(executable)]

NR_TESTS += len(test_executables) * 10

current_test = 1
print("1..{0}".format(NR_TESTS))

if NR_TESTS == 0:
    print("# No test binary found")
    exit(-1)

# Check if a sessiond is running... bail out if none found.
if session_daemon_alive() == 0:
    bail("No sessiond running. Please make sure you are running this test with the \"run\" shell script and verify that the lttng tools are properly installed.")

if DYNAMIC_TEST_ENABLED:
    session_info = create_session()
    enable_ust_tracepoint_event(session_info, "ust_tests_demo*")
    start_session(session_info)

    # Dry run, no events should be logged
    demo_process = subprocess.Popen(test_path + "demo", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    demo_process.wait()
    stop_session(session_info)

    print_test_result(demo_process.returncode == 0, current_test,\
                          "Running application dynamically linked to providers, no preload")
    current_test += 1
    print_test_result(not os.path.exists(session_info.trace_path), current_test,\
                          "No events logged when running demo application without preloading providers")
    current_test += 1

    shutil.rmtree(session_info.tmp_directory)

for executable in test_executables:
    executable_name = os.path.basename(executable)
    session_info = create_session()
    enable_ust_tracepoint_event(session_info, "ust_tests_demo*")
    start_session(session_info)

    demo_process = subprocess.Popen(executable, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    demo_process.wait()
    stop_session(session_info)

    trace_found = os.path.exists(session_info.trace_path)
    print_test_result(trace_found, current_test,\
                          "{0}, resulting trace found".format(executable_name))
    current_test += 1

    if not trace_found:
        print("# Skipping " + executable_name + " trace verification tests")
        continue

    try:
        babeltrace_process = subprocess.Popen(["babeltrace", session_info.trace_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        bail("Could not open babeltrace. Please make sure it is installed.")

    # We should find 8 events in the resulting trace
    event_entries = []
    for event_line in babeltrace_process.stdout:
        event_line = event_line.decode('utf-8').replace("\n", "")
        event_entries.append(event_line)

    if len(event_entries) != 8:
        bail("{0}, wrong number of events found in resulting trace.".format(executable_name))

    shutil.rmtree(session_info.tmp_directory)

    print_test_result(len(event_entries) == 8, current_test,\
                          "{0}, total number of events logged is correct".format(executable_name))
    current_test += 1

    # Check each loop event
    match = re.search(r".*ust_tests_demo:starting.*value = (\d+) ", event_entries[0])
    print_test_result(match is not None and (int(match.group(1)) == 123), current_test,\
                          "{0}, ust_tests_demo:starting event found in trace with a correct integer argument".format(executable_name))
    current_test += 1

    for i in range(5):
        print_test_result(check_ust_test_demo2_event(event_entries[i+1], i), current_test,\
                              "{0}, ust_tests_demo2:loop event found in trace and arguments are correct, iteration ".format(executable_name)\
                              + str(i + 1))
        current_test += 1

    match = re.search(r".*ust_tests_demo:done.*value = (\d+)", event_entries[6])
    print_test_result(match is not None and (int(match.group(1)) == 456), current_test,\
                          "{0}, ust_tests_demo:done event found in resulting trace with a correct integer argument".format(executable_name))
    current_test += 1

    match = re.search(r".*ust_tests_demo3:done.*value = (\d+)", event_entries[7])
    print_test_result(match is not None and (int(match.group(1)) == 42), current_test,\
                          "{0}, ust_tests_demo3:done event found in resulting trace with a correct integer argument".format(executable_name))
    current_test += 1
