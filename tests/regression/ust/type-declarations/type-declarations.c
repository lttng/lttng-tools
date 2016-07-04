/*
 * Copyright (C) 2014 Geneviève Bastien <gbastien@versatic.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

/*
 * This test generates a few events and exits.
 */

#include <unistd.h>

#define TRACEPOINT_DEFINE
#define TRACEPOINT_CREATE_PROBES
#include "ust_tests_td.h"

int main(int argc, char *argv[])
{
	int i;

	for (i = 0; i < 2; i++) {
		tracepoint(ust_tests_td, tptest, i % 2, (i+1) % 2, i % 21);
		tracepoint(ust_tests_td, tptest_bis,  i % 2);
	}

	tracepoint(ust_tests_td, test_auto);

	return 0;
}
