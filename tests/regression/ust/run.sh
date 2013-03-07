#!/bin/bash
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

DIR=$(dirname $0)
TESTDIR=$DIR/../..
source $TESTDIR/utils/runner.sh

#### ADD TESTS HERE ####

tests=( $DIR/test_event_basic
	$DIR/test_event_wildcard
	$DIR/before-after/test_before_after
	$DIR/high-throughput/test_high_throughput
	$DIR/low-throughput/test_low_throughput
	$DIR/multi-session/test_multi_session
	$DIR/nprocesses/test_nprocesses
	$DIR/overlap/test_overlap
	$DIR/buffers-uid/test_buffers_uid )

#### END TESTS HERE ####

opts=("$@")
run_tests tests[@] opts[@]
