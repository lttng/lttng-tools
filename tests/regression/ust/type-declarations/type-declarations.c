/*
 * Copyright (C) 2014 Geneviève Bastien <gbastien@versatic.net>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

/*
 * This test generates a few events and exits.
 */

#include <unistd.h>

#define TRACEPOINT_DEFINE
#define TRACEPOINT_CREATE_PROBES
#include "ust_tests_td.h"

int main(void)
{
	int i;

	for (i = 0; i < 2; i++) {
		tracepoint(ust_tests_td, tptest, i % 2, (i + 1) % 2, i % 21);
		tracepoint(ust_tests_td, tptest_bis, i % 2);
	}

	tracepoint(ust_tests_td, test_auto);

	return 0;
}
