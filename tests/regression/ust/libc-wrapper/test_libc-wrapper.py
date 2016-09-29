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


NR_TESTS = 4
current_test = 1
print("1..{0}".format(NR_TESTS))

# Check if a sessiond is running... bail out if none found.
if session_daemon_alive() == 0:
    bail("No sessiond running. Please make sure you are running this test with the \"run\" shell script and verify that the lttng tools are properly installed.")

session_info = create_session()
enable_ust_tracepoint_event(session_info, "lttng_ust_libc*")
start_session(session_info)

malloc_process = subprocess.Popen(test_path + "prog", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
malloc_process.wait()

print_test_result(malloc_process.returncode == 0, current_test, "Test application exited normally")
current_test += 1

stop_session(session_info)

# Check for malloc events in the resulting trace
try:
    babeltrace_process = subprocess.Popen(["babeltrace", session_info.trace_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
except FileNotFoundError:
    bail("Could not open babeltrace. Please make sure it is installed.", session_info)

malloc_event_found = False
free_event_found = False

for event_line in babeltrace_process.stdout:
    # Let babeltrace finish to get the return code
    if malloc_event_found and free_event_found:
        continue

    event_line = event_line.decode('utf-8').replace("\n", "")
    if re.search(r".*lttng_ust_libc:malloc.*", event_line) is not None:
        malloc_event_found = True

    if re.search(r".*lttng_ust_libc:free.*", event_line) is not None:
        free_event_found = True

babeltrace_process.wait()

print_test_result(babeltrace_process.returncode == 0, current_test, "Resulting trace is readable")
current_test += 1

print_test_result(malloc_event_found, current_test, "lttng_ust_libc:malloc event found in resulting trace")
current_test += 1

print_test_result(free_event_found, current_test, "lttng_ust_libc:free event found in resulting trace")
current_test += 1

shutil.rmtree(session_info.tmp_directory)
