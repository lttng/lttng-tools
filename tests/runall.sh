#!/bin/bash
#
# Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

TEST_DIR=$(dirname $0)

failed=0
num_test=1

function run() {
	printf "%d) Running test $@\n" $num_test
	echo "=================================="

	# Running test
	./$@
	if [ $? -ne 0 ]; then
		let failed=$failed+1
		printf "\nTest $@ FAILED\n\n"
	else
		printf "\nTest $@ PASSED\n\n"
	fi

	let num_test=$num_test+1
}

#### ADD TESTS HERE ####

#### END TESTS HERE ####

echo "--------------------------"
if [ $failed -eq 0 ]; then
	echo "All passed!"
else
	echo "$failed tests failed"
fi
echo "--------------------------"

exit 0
