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


NR_TESTS = 6
current_test = 1
print("1..{0}".format(NR_TESTS))

# Check if a sessiond is running... bail out if none found.
if session_daemon_alive() == 0:
    bail("No sessiond running. Please make sure you are running this test with the \"run\" shell script and verify that the lttng tools are properly installed.")

session_info = create_session()
enable_ust_tracepoint_event(session_info, "ust_tests_fork*")
start_session(session_info)

fork_process = subprocess.Popen([test_path + "fork", test_path + "fork2"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
parent_pid = -1
child_pid = -1
for line in fork_process.stdout:
    line = line.decode('utf-8').replace("\n", "")
    match = re.search(r"child_pid (\d+)", line)
    if match:
        child_pid = match.group(1)
    match = re.search(r"parent_pid (\d+)", line)
    if match:
        parent_pid = match.group(1)

fork_process.wait()

print_test_result(fork_process.returncode == 0, current_test, "Fork test application exited normally")
current_test += 1

stop_session(session_info)

# Check both events (normal exit and suicide messages) are present in the resulting trace
try:
    babeltrace_process = subprocess.Popen(["babeltrace", session_info.trace_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
except FileNotFoundError:
    bail("Could not open babeltrace. Please make sure it is installed.", session_info)

event_lines = []
for event_line in babeltrace_process.stdout:
    event_line = event_line.decode('utf-8').replace("\n", "")
    if re.search(r"warning", event_line) is not None or re.search(r"error", event_line) is not None:
        print( "# " + event_line )
    else:
        event_lines.append(event_line)

babeltrace_process.wait()

print_test_result(babeltrace_process.returncode == 0, current_test, "Resulting trace is readable")
current_test += 1

if babeltrace_process.returncode != 0:
    bail("Unreadable trace; can't proceed with analysis.", session_info)

event_before_fork = False
event_after_fork_parent = False
event_after_fork_child = False
event_after_exec = False

for event_line in event_lines:
    match = re.search(r".*pid = (\d+)", event_line)
    if match is not None:
        event_pid = match.group(1)
    else:
        continue

    if re.search(r"before_fork", event_line):
        event_before_fork = (event_pid == parent_pid)
    if re.search(r"after_fork_parent", event_line):
        event_after_fork_parent = (event_pid == parent_pid)
    if re.search(r"after_fork_child", event_line):
        event_after_fork_child = (event_pid == child_pid)
    if re.search(r"after_exec", event_line):
        event_after_exec = (event_pid == child_pid)

print_test_result(event_before_fork, current_test, "before_fork event logged by parent process found in trace")
current_test += 1
print_test_result(event_after_fork_parent, current_test, "after_fork_parent event logged by parent process found in trace")
current_test += 1
print_test_result(event_after_fork_child, current_test, "after_fork_child event logged by child process found in trace")
current_test += 1
print_test_result(event_after_exec, current_test, "after_exec event logged by child process found in trace")
current_test += 1

shutil.rmtree(session_info.tmp_directory)
