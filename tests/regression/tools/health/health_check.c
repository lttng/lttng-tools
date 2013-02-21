/*
 * Copyright (C) 2012 - Christian Babeux <christian.babeux@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>

#include "lttng/lttng.h"

#define HEALTH_CMD_FAIL     (1 << 0)
#define HEALTH_APP_MNG_FAIL (1 << 1)
#define HEALTH_APP_REG_FAIL (1 << 2)
#define HEALTH_KERNEL_FAIL  (1 << 3)
#define HEALTH_CSMR_FAIL    (1 << 4)

int main(int argc, char *argv[])
{
	int health = -1;
	int status = 0;

	/* Command thread */
	health = lttng_health_check(LTTNG_HEALTH_CMD);
	printf("Health check cmd: %d\n", health);

	if (health) {
		status |= HEALTH_CMD_FAIL;
	}

	/* App manage thread */
	health = lttng_health_check(LTTNG_HEALTH_APP_MANAGE);
	printf("Health check app. manage: %d\n", health);

	if (health) {
		status |= HEALTH_APP_MNG_FAIL;
	}
	/* App registration thread */
	health = lttng_health_check(LTTNG_HEALTH_APP_REG);
	printf("Health check app. registration: %d\n", health);

	if (health) {
		status |= HEALTH_APP_REG_FAIL;
	}

	/* Kernel thread */
	health = lttng_health_check(LTTNG_HEALTH_KERNEL);
	printf("Health check kernel: %d\n", health);

	if (health) {
		status |= HEALTH_KERNEL_FAIL;
	}

	/* Consumer thread */
	health = lttng_health_check(LTTNG_HEALTH_CONSUMER);
	printf("Health check consumer: %d\n", health);

	if (health) {
		status |= HEALTH_CSMR_FAIL;
	}

	return status;
}
