/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "cpu.h"

cycles_t get_cycles(void)
{
	return caa_get_cycles();
}

uint64_t get_cpu_freq(void)
{
	struct timezone tz;
	struct timeval tvstart, tvstop;
	cycles_t c_before, c_after;
	unsigned long microseconds;

	memset(&tz, 0, sizeof(tz));

	gettimeofday(&tvstart, &tz);
	c_before = get_cycles();
	gettimeofday(&tvstart, &tz);

	sleep(1);

	gettimeofday(&tvstop, &tz);
	c_after = get_cycles();
	gettimeofday(&tvstop, &tz);

	microseconds = ((tvstop.tv_sec - tvstart.tv_sec) * 1000000) +
		(tvstop.tv_usec - tvstart.tv_usec);

	return (uint64_t) ((c_after - c_before) / microseconds);
}
