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

function run_tests
{
	declare -a tests=("${!1}")
	declare -a tests_opts=("${!2}")

	gentap=0

	for test_opt in ${tests_opts[@]};
	do
	    case "$test_opt" in
		--generate-tap-files) gentap=1 ;;
		*) ;;
	    esac
	done

	for bin in ${tests[@]};
	do
		if [ ! -e $bin ]; then
			echo -e "$bin not found, skipping."
			continue
		fi

		if [ "$gentap" -eq 1 ]; then
			./$bin > ${bin}.tap 2>&1
		else
			./$bin
		fi
	done
}
