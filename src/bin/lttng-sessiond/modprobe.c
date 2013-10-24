/*
 * Copyright (C) 2011 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>

#include <common/common.h>

#include "modprobe.h"
#include "kern-modules.h"

/* MUST be loaded first */
const struct kern_modules_param kern_modules_control[] = {
	{ "lttng-tracer", 1 },
};

/* LTTng kernel tracer modules list */
const struct kern_modules_param kern_modules_list[] = {
	{ "lttng-ftrace", 0 },
	{ "lttng-kprobes", 0 },
	{ "lttng-kretprobes", 0 },
	{ "lttng-lib-ring-buffer", 1 },
	{ "lttng-ring-buffer-client-discard", 1 },
	{ "lttng-ring-buffer-client-overwrite", 1 },
	{ "lttng-ring-buffer-metadata-client", 1 },
	{ "lttng-ring-buffer-client-mmap-discard", 1 },
	{ "lttng-ring-buffer-client-mmap-overwrite", 1 },
	{ "lttng-ring-buffer-metadata-mmap-client", 1 },
	{ "lttng-types", 0 },
	{ "lttng-probe-asoc", 0 },
	{ "lttng-probe-block", 0 },
	{ "lttng-probe-btrfs", 0 },
	{ "lttng-probe-compaction", 0 },
	{ "lttng-probe-ext3", 0 },
	{ "lttng-probe-ext4", 0 },
	{ "lttng-probe-gpio", 0 },
	{ "lttng-probe-irq", 0 },
	{ "lttng-probe-jbd", 0 },
	{ "lttng-probe-jbd2", 0 },
	{ "lttng-probe-kmem", 0 },
	{ "lttng-probe-kvm", 0 },
	{ "lttng-probe-kvm-x86", 0 },
	{ "lttng-probe-kvm-x86-mmu", 0 },
	{ "lttng-probe-lock", 0 },
	{ "lttng-probe-module", 0 },
	{ "lttng-probe-napi", 0 },
	{ "lttng-probe-net", 0 },
	{ "lttng-probe-power", 0 },
	{ "lttng-probe-printk", 0 },
	{ "lttng-probe-random", 0 },
	{ "lttng-probe-rcu", 0 },
	{ "lttng-probe-regmap", 0 },
	{ "lttng-probe-regulator", 0 },
	{ "lttng-probe-rpm", 0 },
	{ "lttng-probe-sched", 0 },
	{ "lttng-probe-scsi", 0 },
	{ "lttng-probe-signal", 0 },
	{ "lttng-probe-skb", 0 },
	{ "lttng-probe-sock", 0 },
	{ "lttng-probe-statedump", 0 },
	{ "lttng-probe-sunrpc", 0 },
	{ "lttng-probe-timer", 0 },
	{ "lttng-probe-udp", 0 },
	{ "lttng-probe-vmscan", 0 },
	{ "lttng-probe-workqueue", 0 },
	{ "lttng-probe-writeback", 0 },
};

/*
 * Remove control kernel module(s) in reverse load order.
 */
void modprobe_remove_lttng_control(void)
{
	int ret = 0, i;
	char modprobe[256];

	for (i = ARRAY_SIZE(kern_modules_control) - 1; i >= 0; i--) {
		ret = snprintf(modprobe, sizeof(modprobe),
				"/sbin/modprobe -r -q %s",
				kern_modules_control[i].name);
		if (ret < 0) {
			PERROR("snprintf modprobe -r");
			goto error;
		}
		modprobe[sizeof(modprobe) - 1] = '\0';
		ret = system(modprobe);
		if (ret == -1) {
			ERR("Unable to launch modprobe -r for module %s",
					kern_modules_control[i].name);
		} else if (kern_modules_control[i].required
				&& WEXITSTATUS(ret) != 0) {
			ERR("Unable to remove module %s",
					kern_modules_control[i].name);
		} else {
			DBG("Modprobe removal successful %s",
					kern_modules_control[i].name);
		}
	}

error:
	return;
}

/*
 * Remove data kernel modules in reverse load order.
 */
void modprobe_remove_lttng_data(void)
{
	int ret = 0, i;
	char modprobe[256];

	for (i = ARRAY_SIZE(kern_modules_list) - 1; i >= 0; i--) {
		ret = snprintf(modprobe, sizeof(modprobe),
				"/sbin/modprobe -r -q %s",
				kern_modules_list[i].name);
		if (ret < 0) {
			PERROR("snprintf modprobe -r");
			goto error;
		}
		modprobe[sizeof(modprobe) - 1] = '\0';
		ret = system(modprobe);
		if (ret == -1) {
			ERR("Unable to launch modprobe -r for module %s",
					kern_modules_list[i].name);
		} else if (kern_modules_list[i].required
				&& WEXITSTATUS(ret) != 0) {
			ERR("Unable to remove module %s",
					kern_modules_list[i].name);
		} else {
			DBG("Modprobe removal successful %s",
					kern_modules_list[i].name);
		}
	}

error:
	return;
}

/*
 * Remove all kernel modules in reverse order.
 */
void modprobe_remove_lttng_all(void)
{
	modprobe_remove_lttng_data();
	modprobe_remove_lttng_control();
}

/*
 * Load control kernel module(s).
 */
int modprobe_lttng_control(void)
{
	int ret = 0, i;
	char modprobe[256];

	for (i = 0; i < ARRAY_SIZE(kern_modules_control); i++) {
		ret = snprintf(modprobe, sizeof(modprobe),
				"/sbin/modprobe %s%s",
				kern_modules_control[i].required ? "" : "-q ",
				kern_modules_control[i].name);
		if (ret < 0) {
			PERROR("snprintf modprobe");
			goto error;
		}
		modprobe[sizeof(modprobe) - 1] = '\0';
		ret = system(modprobe);
		if (ret == -1) {
			ERR("Unable to launch modprobe for module %s",
					kern_modules_control[i].name);
		} else if (kern_modules_control[i].required
				&& WEXITSTATUS(ret) != 0) {
			ERR("Unable to load module %s",
					kern_modules_control[i].name);
		} else {
			DBG("Modprobe successfully %s",
					kern_modules_control[i].name);
		}
	}

error:
	return ret;
}

/*
 * Load data kernel module(s).
 */
int modprobe_lttng_data(void)
{
	int ret = 0, i;
	char modprobe[256];

	for (i = 0; i < ARRAY_SIZE(kern_modules_list); i++) {
		ret = snprintf(modprobe, sizeof(modprobe),
				"/sbin/modprobe %s%s",
				kern_modules_list[i].required ? "" : "-q ",
				kern_modules_list[i].name);
		if (ret < 0) {
			PERROR("snprintf modprobe");
			goto error;
		}
		modprobe[sizeof(modprobe) - 1] = '\0';
		ret = system(modprobe);
		if (ret == -1) {
			ERR("Unable to launch modprobe for module %s",
					kern_modules_list[i].name);
		} else if (kern_modules_list[i].required
				&& WEXITSTATUS(ret) != 0) {
			ERR("Unable to load module %s",
					kern_modules_list[i].name);
		} else {
			DBG("Modprobe successfully %s",
					kern_modules_list[i].name);
		}
	}

error:
	return ret;
}

/*
 * Load all lttng kernel modules.
 */
int modprobe_lttng_all(void)
{
	int ret;

	ret = modprobe_lttng_control();
	if (ret < 0) {
		goto error;
	}

	ret = modprobe_lttng_data();
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}
