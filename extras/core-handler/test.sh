#!/bin/sh
#
# Copyright (C) 2013 - Christian Babeux <christian.babeux@efficios.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; only version 2
# of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#

LTTNG_BIN="lttng"

CHANNEL_NAME="chan"
EVENT_NAME="sched_switch"

echo "Setup..."
$LTTNG_BIN create --no-output
$LTTNG_BIN enable-channel "${CHANNEL_NAME}" -k --overwrite --output mmap
$LTTNG_BIN enable-event "${EVENT_NAME}" -c "${CHANNEL_NAME}" -k
$LTTNG_BIN start

echo "Sleeping..."
sleep 10

echo "Crashing..."
$(dirname $0)/crash

echo "Sleeping..."
sleep 10

$LTTNG_BIN stop
$LTTNG_BIN destroy

echo "Core dump and snapshot will be available in /tmp/lttng/{core,snapshot}."
