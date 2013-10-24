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

SESSION_NAME="coredump-handler"

# Just recording kernel event sched_switch as an example, but we can as
# well record user-space events from UST domain.
EVENT_NAME="sched_switch"

SNAPSHOT_PATH="/tmp/lttng/snapshot"
SNAPSHOT_URI="file://${SNAPSHOT_PATH}"

echo "Setup ${SESSION_NAME}..."
$LTTNG_BIN create ${SESSION_NAME} --snapshot -U ${SNAPSHOT_PATH}
$LTTNG_BIN enable-event ${EVENT_NAME} -k -s ${SESSION_NAME}
$LTTNG_BIN start ${SESSION_NAME}

echo "Sleeping..."
sleep 10

echo "Crashing..."
$(dirname $0)/crash

echo "Sleeping..."
sleep 10

$LTTNG_BIN stop ${SESSION_NAME}
$LTTNG_BIN destroy ${SESSION_NAME}

echo "Core dump will be available in /tmp/lttng/core."
echo "Snapshot will be available in ${SNAPSHOT_PATH}."
