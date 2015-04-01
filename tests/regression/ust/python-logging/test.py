# Copyright (C) 2015 - Philippe Proulx <pproulx@efficios.com>
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

from __future__ import unicode_literals, print_function
import logging
import time
import sys


def _perror(msg):
    print(msg, file=sys.stderr)
    sys.exit(1)


try:
    import lttngust
except (ImportError) as e:
    _perror('lttngust package not found: {}'.format(e))


def _main():
    ev1 = logging.getLogger('python-ev-test1');
    ev2 = logging.getLogger('python-ev-test2');

    logging.basicConfig()

    try:
        nr_iter = int(sys.argv[1])
        wait_time = float(sys.argv[2])
        fire_debug_ev = False
        fire_second_ev = False
    except (IndexError) as e:
        _perror('missing arguments: {}'.format(e))
    except (ValueError) as e:
        _perror('invalid arguments: {}'.format(e))

    try:
        if len(sys.argv) > 3:
            fire_debug_ev = int(sys.argv[3])
        if len(sys.argv) > 4:
            fire_second_ev = int(sys.argv[4])
    except (ValueError) as e:
        _perror('invalid arguments: {}'.format(e))

    for i in range(nr_iter):
        ev1.info('{} fired [INFO]'.format(ev1.name))

        if fire_debug_ev:
            ev1.debug('{} fired [DEBUG]'.format(ev1.name))

        time.sleep(wait_time)

    if fire_second_ev:
        ev2.info('{} fired [INFO]'.format(ev2.name))


if __name__ == '__main__':
    _main()
