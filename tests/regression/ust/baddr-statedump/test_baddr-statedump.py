#!/usr/bin/env python3
#
# Copyright (C) - 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# Copyright (C) - 2015 Antoine Busque <abusque@efficios.com>
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


NR_TESTS = 7
current_test = 1
print("1..{0}".format(NR_TESTS))

# Check if a sessiond is running... bail out if none found.
if session_daemon_alive() == 0:
    bail("""No sessiond running. Please make sure you are running this test
    with the "run" shell script and verify that the lttng tools are
    properly installed.""")

session_info = create_session()
enable_ust_tracepoint_event(session_info, "*")
start_session(session_info)

test_process = subprocess.Popen(test_path + "prog.strip", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
test_process.wait()

print_test_result(test_process.returncode == 0, current_test, "Test application exited normally")
current_test += 1

stop_session(session_info)

# Check for statedump events in the resulting trace
try:
    babeltrace_process = subprocess.Popen(["babeltrace", session_info.trace_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
except FileNotFoundError:
    bail("Could not open babeltrace. Please make sure it is installed.", session_info)

start_event_found = False
bin_info_event_found = False
build_id_event_found = False
debug_link_event_found = False
end_event_found = False

for event_line in babeltrace_process.stdout:
    # Let babeltrace finish to get the return code
    if start_event_found and bin_info_event_found and build_id_event_found and \
       debug_link_event_found and end_event_found:
        continue

    event_line = event_line.decode('utf-8').replace("\n", "")
    if re.search(r".*lttng_ust_statedump:start.*", event_line) is not None:
        start_event_found = True
    elif re.search(r".*lttng_ust_statedump:bin_info.*", event_line) is not None:
        bin_info_event_found = True
    elif re.search(r".*lttng_ust_statedump:build_id.*", event_line) is not None:
        build_id_event_found = True
    elif re.search(r".*lttng_ust_statedump:debug_link.*", event_line) is not None:
        debug_link_event_found = True
    elif re.search(r".*lttng_ust_statedump:end.*", event_line) is not None:
        end_event_found = True

babeltrace_process.wait()

print_test_result(babeltrace_process.returncode == 0, current_test, "Resulting trace is readable")
current_test += 1

print_test_result(start_event_found, current_test, "lttng_ust_statedump:start event found in resulting trace")
current_test += 1

print_test_result(bin_info_event_found, current_test, "lttng_ust_statedump:bin_info event found in resulting trace")
current_test += 1

print_test_result(build_id_event_found, current_test, "lttng_ust_statedump:build_id event found in resulting trace")
current_test += 1

print_test_result(debug_link_event_found, current_test, "lttng_ust_statedump:debug_link event found in resulting trace")
current_test += 1

print_test_result(end_event_found, current_test, "lttng_ust_statedump:end event found in resulting trace")
current_test += 1

shutil.rmtree(session_info.tmp_directory)
