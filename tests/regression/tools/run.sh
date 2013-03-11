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

tests=( $DIR/filtering/test_invalid_filter
	$DIR/filtering/test_unsupported_op
	$DIR/filtering/test_valid_filter
	$DIR/health/test_thread_exit
	$DIR/health/test_thread_stall
	$DIR/health/test_tp_fail
	$DIR/streaming/test_kernel
	$DIR/streaming/test_ust
	$DIR/streaming/test_high_throughput_limits )

#### END TESTS HERE ####

opts=("$@")
run_tests tests[@] opts[@]
