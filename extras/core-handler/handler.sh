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

# System binaries paths.
CAT_BIN="cat"
PGREP_BIN="pgrep"
MKDIR_BIN="mkdir"
LTTNG_BIN="lttng"

# Session name
SESSION_NAME="coredump-handler"

# Sessiond binary name.
SESSIOND_BIN_NAME="lttng-sessiond"

# TODO: Checking for a sessiond lockfile would be more appropriate.
if $PGREP_BIN -u root "${SESSIOND_BIN_NAME}" > /dev/null 2>&1
then
    $LTTNG_BIN snapshot record -s ${SESSION_NAME} > /dev/null 2>&1
fi

# Core file settings.
CORE_PATH="/tmp/lttng/core"
CORE_PREFIX="core"

# Core specifiers, see man core(5)

p=$1 # PID of dumped process
u=$2 # (numeric) real UID of dumped process
g=$3 # (numeric) real GID of dumped process
s=$4 # number of signal causing dump
t=$5 # time of dump, expressed as seconds since the Epoch,
     # 1970-01-01 00:00:00 +0000 (UTC)
h=$6 # hostname (same as nodename returned by uname(2))
e=$7 # executable filename (without path prefix)
E=$8 # pathname of executable, with slashes ('/') replaced
     # by exclamation marks ('!').
c=$9 # core file size soft resource limit of crashing process
     # (since Linux 2.6.24)

# Save core dump from stdin.
$MKDIR_BIN -p "${CORE_PATH}"
$CAT_BIN - > "${CORE_PATH}/${CORE_PREFIX}.$p"

# Optional, chain core dump handler with original systemd script.
#$CAT_BIN - | /usr/lib/systemd/systemd-coredump $p $u $g $s $t $e
