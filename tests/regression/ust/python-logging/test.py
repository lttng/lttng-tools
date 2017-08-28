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
import argparse
import os


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

    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--nr-iter', required=True)
    parser.add_argument('-s', '--wait', required=True)
    parser.add_argument('-d', '--fire-debug-event', action="store_true")
    parser.add_argument('-e', '--fire-second-event', action="store_true")
    parser.add_argument('-r', '--ready-file')
    parser.add_argument('-g', '--go-file')
    args = parser.parse_args()

    nr_iter = int(args.nr_iter)
    wait_time = float(args.wait)
    fire_debug_ev = args.fire_debug_event
    fire_second_ev = args.fire_second_event

    ready_file = args.ready_file
    go_file = args.go_file

    if ready_file is not None and os.path.exists(ready_file):
        raise ValueError('Ready file already exist')

    if go_file is not None and os.path.exists(go_file):
        raise ValueError('Go file already exist. Review synchronization')

    if (ready_file is None) != (go_file is None):
        raise ValueError('--go-file and --ready-file need each others, review'
                'synchronization')


    # Inform that we are ready, if necessary
    if ready_file is not None:
        open(ready_file, 'a').close()

    # Wait for go, if necessary
    while go_file is not None and not os.path.exists(go_file):
        time.sleep(0.5)

    for i in range(nr_iter):
        ev1.info('{} fired [INFO]'.format(ev1.name))

        if fire_debug_ev:
            ev1.debug('{} fired [DEBUG]'.format(ev1.name))

        time.sleep(wait_time)

    if fire_second_ev:
        ev2.info('{} fired [INFO]'.format(ev2.name))

    if ready_file is not None:
        try:
            os.unlink(ready_file)
        except:
            print("Unexpected error on ready file unlink:", sys.exc_info()[0])
            raise


if __name__ == '__main__':
    _main()
