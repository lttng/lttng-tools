#!/usr/bin/env python3
#
# Copyright (C) - 2014 Geneviève Bastien <gbastien@versatic.net>
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

NR_TESTS = 10
current_test = 1
print("1..{0}".format(NR_TESTS))

# Check if a sessiond is running... bail out if none found.
if session_daemon_alive() == 0:
    bail("No sessiond running. Please make sure you are running this test with the \"run\" shell script and verify that the lttng tools are properly installed.")

session_info = create_session()
enable_ust_tracepoint_event(session_info, "ust_tests_td*")
start_session(session_info)

test_env = os.environ.copy()
test_env["LTTNG_UST_REGISTER_TIMEOUT"] = "-1"

td_process = subprocess.Popen(test_path + "type-declarations", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=test_env)
td_process.wait()

print_test_result(td_process.returncode == 0, current_test, "Test application exited normally")
current_test += 1

stop_session(session_info)

# Check event fields using type declarations are present
try:
    babeltrace_process = subprocess.Popen(["babeltrace", session_info.trace_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
except FileNotFoundError:
    bail("Could not open babeltrace. Please make sure it is installed.")

event_lines = []
for event_line in babeltrace_process.stdout:
    event_line = event_line.decode('utf-8').replace("\n", "")
    event_lines.append(event_line)
babeltrace_process.wait()

print_test_result(babeltrace_process.returncode == 0, current_test, "Resulting trace is readable")
current_test += 1

if babeltrace_process.returncode != 0:
    bail("Unreadable trace; can't proceed with analysis.")

print_test_result(len(event_lines) == 5, current_test, "Correct number of events found in resulting trace")
current_test += 1

if len(event_lines) != 5:
    bail("Unexpected number of events found in resulting trace (" + session_info.trace_path + ")." )

match = re.search(r".*ust_tests_td:(.*):.*enumfield = \( \"(.*)\" :.*enumfield_bis = \( \"(.*)\" :.*enumfield_third = .*:.*", event_lines[0])
print_test_result(match is not None and match.group(1) == "tptest", current_test,\
                      "First tracepoint is present")
current_test += 1

print_test_result(match is not None and match.group(2) == "zero", current_test,\
                      "First tracepoint's enum value maps to zero")
current_test += 1

print_test_result(match is not None and match.group(3) == "one", current_test,\
                      "First tracepoint's second enum value maps to one")
current_test += 1

match = re.search(r".*ust_tests_td:(.*):.*enumfield = \( \"(.*)\" :.*", event_lines[1])
print_test_result(match is not None and match.group(1) == "tptest_bis", current_test,\
                      "Second tracepoint is present")
current_test += 1

print_test_result(match is not None and match.group(2) == "zero", current_test,\
                      "Second tracepoint's enum value maps to zero")
current_test += 1

match = re.search(r".*ust_tests_td:(.*):.*enumfield = \( \"(.*)\" :.*enumfield_bis = \( \"(.*)\" .*", event_lines[2])

print_test_result(match is not None and match.group(2) == "one", current_test,\
                      "Third tracepoint's enum value maps to one")
current_test += 1

print_test_result('{ zero = ( "zero" : container = 0 ), two = ( "two" : container = 2 ), three = ( "three" : container = 3 ), fifteen = ( "ten_to_twenty" : container = 15 ), twenty_one = ( "twenty_one" : container = 21 ) }' in event_lines[4],
                  current_test, 'Auto-incrementing enum values are correct')

shutil.rmtree(session_info.tmp_directory)
