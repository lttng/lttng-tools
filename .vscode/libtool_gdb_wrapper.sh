#!/usr/bin/env sh
# SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
# Wrapper script to setup the environment before invoking gdb
# on the in-tree binaries (under `.libs`)

CURDIR=$(dirname "$0")/
export LD_LIBRARY_PATH="$CURDIR/../src/lib/lttng-ctl/.libs:$LD_LIBRARY_PATH"

libtool --mode=execute gdb "$@"
