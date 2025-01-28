#!/bin/sh
#
# SPDX-FileCopyrightText: 2013 Christian Babeux <christian.babeux@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only
#

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
