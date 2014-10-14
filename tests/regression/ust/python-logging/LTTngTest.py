#!/usr/bin/env python
#
# Copyright (C) 2014 - David Goulet <dgoulet@efficios.com>
#
# This library is free software; you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; version 2.1 of the License.
#
# This library is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA

import sys
import logging
import errno

from time import sleep

def cleanup(code, agent = None):
    """
    Cleanup agent and exit with given code.
    """
    if agent is not None:
        agent.destroy()

    sys.exit(code)

try:
    import lttng_agent
except ImportError as e:
    print("LTTng Agent not found. Aborting")
    cleanup(errno.ENOSYS)

def run():
    """
    Main for this test program. Based on the Java testing program that behaves
    exactly the same.
    """

    agent = lttng_agent.LTTngAgent()
    ev1 = logging.getLogger("python-ev-test1");
    ev2 = logging.getLogger("python-ev-test2");

    try:
        nr_iter = int(sys.argv[1])
        wait_time = int(sys.argv[2])
        fire_debug_ev = 0
        fire_second_ev = 0
    except IndexError as e:
        print("Missing arguments. Aborting")
        cleanup(errno.EINVAL, agent)
    except ValueError as e:
        print("Invalid arguments. Aborting")
        cleanup(errno.EINVAL, agent)

    if len(sys.argv) > 3:
        fire_debug_ev = int(sys.argv[3])
    if len(sys.argv) > 4:
        fire_second_ev = int(sys.argv[4])

    for i in range(0, nr_iter):
        ev1.info("%s fired" % ev1.name)
        if fire_debug_ev != 0:
            ev1.debug("%s DEBUG fired" % ev1.name)
        sleep(wait_time)

    if fire_second_ev != 0:
        ev2.info("%s fired" % ev2.name)

if __name__ == "__main__":
    run()
