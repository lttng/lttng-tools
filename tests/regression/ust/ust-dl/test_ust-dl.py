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


have_dlmopen = (os.environ.get('LTTNG_TOOLS_HAVE_DLMOPEN') == '1')


NR_TESTS = 14
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

test_env = os.environ.copy()
test_env["LD_PRELOAD"] = test_env.get("LD_PRELOAD", "") + ":liblttng-ust-dl.so"
test_env["LD_LIBRARY_PATH"] = test_env.get("LD_LIBRARY_PATH", "") + ":" + test_path
test_process = subprocess.Popen(test_path + "prog",
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                env=test_env)
test_process.wait()

print_test_result(test_process.returncode == 0, current_test, "Test application exited normally")
current_test += 1

stop_session(session_info)

# Check for dl events in the resulting trace
try:
    babeltrace_process = subprocess.Popen(["babeltrace", session_info.trace_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
except FileNotFoundError:
    bail("Could not open babeltrace. Please make sure it is installed.", session_info)

dlopen_event_found = 0
dlmopen_event_found = 0
build_id_event_found = 0
debug_link_event_found = 0
dlclose_event_found = 0
load_event_found = 0
load_build_id_event_found = 0
load_debug_link_event_found = 0
unload_event_found = 0
load_libfoo_found = 0
load_libbar_found = 0
load_libzzz_found = 0

for event_line in babeltrace_process.stdout:

    event_line = event_line.decode('utf-8').replace("\n", "")
    if re.search(r".*lttng_ust_dl:dlopen.*", event_line) is not None:
        dlopen_event_found += 1
    elif re.search(r".*lttng_ust_dl:dlmopen.*", event_line) is not None:
        dlmopen_event_found += 1
    elif re.search(r".*lttng_ust_dl:build_id.*", event_line) is not None:
        build_id_event_found += 1
    elif re.search(r".*lttng_ust_dl:debug_link.*", event_line) is not None:
        debug_link_event_found += 1
    elif re.search(r".*lttng_ust_dl:dlclose.*", event_line) is not None:
        dlclose_event_found += 1
    elif re.search(r".*lttng_ust_lib:build_id.*", event_line) is not None:
        load_build_id_event_found += 1
    elif re.search(r".*lttng_ust_lib:debug_link.*", event_line) is not None:
        load_debug_link_event_found += 1
    elif re.search(r".*lttng_ust_lib:unload.*", event_line) is not None:
        unload_event_found += 1
    elif re.search(r".*lttng_ust_lib:load.*", event_line) is not None:
        load_event_found += 1
        if re.search(r".*lttng_ust_lib:load.*libfoo.*", event_line) is not None:
            load_libfoo_found += 1
        elif re.search(r".*lttng_ust_lib:load.*libbar.*", event_line) is not None:
            load_libbar_found += 1
        elif re.search(r".*lttng_ust_lib:load.*libzzz.*", event_line) is not None:
            load_libzzz_found += 1

babeltrace_process.wait()

print_test_result(babeltrace_process.returncode == 0, current_test, "Resulting trace is readable")
current_test += 1

print_test_result(dlopen_event_found > 0, current_test, "lttng_ust_dl:dlopen event found in resulting trace")
current_test += 1

if have_dlmopen:
    print_test_result(dlmopen_event_found > 0, current_test, "lttng_ust_dl:dlmopen event found in resulting trace")
else:
    skip_test(current_test, 'dlmopen() is not available')

current_test += 1

print_test_result(build_id_event_found > 0, current_test, "lttng_ust_dl:build_id event found in resulting trace")
current_test += 1

print_test_result(debug_link_event_found > 0, current_test, "lttng_ust_dl:debug_link event found in resulting trace")
current_test += 1

print_test_result(dlclose_event_found > 0, current_test, "lttng_ust_dl:dlclose event found in resulting trace")
current_test += 1

print_test_result(load_event_found > 0, current_test, "lttng_ust_lib:load event found in resulting trace")
current_test += 1

print_test_result(load_build_id_event_found > 0, current_test, "lttng_ust_lib:build_id event found in resulting trace")
current_test += 1

print_test_result(load_debug_link_event_found > 0, current_test, "lttng_ust_lib:debug_link event found in resulting trace")
current_test += 1

print_test_result(unload_event_found == 3, current_test, "lttng_ust_lib:unload event found 3 times in resulting trace")
current_test += 1

print_test_result(load_libfoo_found == 1, current_test, "lttng_ust_lib:load libfoo.so event found once in resulting trace")
current_test += 1

print_test_result(load_libbar_found == 1, current_test, "lttng_ust_lib:load libbar.so event found once in resulting trace")
current_test += 1

print_test_result(load_libzzz_found == 1, current_test, "lttng_ust_lib:load libzzz.so event found once in resulting trace")
current_test += 1

shutil.rmtree(session_info.tmp_directory)
