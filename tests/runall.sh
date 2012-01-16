#!/bin/bash
#
# Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
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

#### ADD TESTS HERE ####

test_suite=( test_sessions test_kernel_data_trace test_ust_data_trace
			lttng/runall.sh ust-nevents/run )

#### END TESTS HERE ####

TESTDIR=$(dirname $0)

source $TESTDIR/utils.sh

start_sessiond
if [ $? -ne 0 ]; then
	exit 1
fi

for bin in ${test_suite[@]};
do
	./$bin
	# Test must return 0 to pass.
	if [ $? -ne 0 ]; then
		echo -e '\e[1;31mFAIL\e[0m'
		echo ""
		stop_sessiond
		exit 1
	fi
done

echo ""
stop_sessiond
exit 0
