/*
 * Copyright (C) 2011 - David Goulet <dgoulet@efficios.com>
 *               2014 - Jan Glauber <jan.glauber@gmail.com>
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

#define _LGPL_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>

#include <common/common.h>
#include <common/utils.h>

#include "modprobe.h"
#include "kern-modules.h"

#define LTTNG_MOD_REQUIRED	1
#define LTTNG_MOD_OPTIONAL	0

/* LTTng kernel tracer mandatory core modules list */
struct kern_modules_param kern_modules_control_core[] = {
	{ "lttng-tracer" },	/* MUST be loaded first so keep at top */
	{ "lttng-lib-ring-buffer" },
	{ "lttng-ring-buffer-client-discard" },
	{ "lttng-ring-buffer-client-overwrite" },
	{ "lttng-ring-buffer-metadata-client" },
	{ "lttng-ring-buffer-client-mmap-discard" },
	{ "lttng-ring-buffer-client-mmap-overwrite" },
	{ "lttng-ring-buffer-metadata-mmap-client" },
};

/* LTTng kernel tracer optional base modules list */
struct kern_modules_param kern_modules_control_opt[] = {
	{ "lttng-types" },
	{ "lttng-ftrace" },
	{ "lttng-kprobes" },
	{ "lttng-kretprobes" },
};

/* LTTng kernel tracer probe modules list */
struct kern_modules_param kern_modules_probes_default[] = {
	{ "lttng-probe-asoc" },
	{ "lttng-probe-block" },
	{ "lttng-probe-btrfs" },
	{ "lttng-probe-compaction" },
	{ "lttng-probe-ext3" },
	{ "lttng-probe-ext4" },
	{ "lttng-probe-gpio" },
	{ "lttng-probe-irq" },
	{ "lttng-probe-jbd" },
	{ "lttng-probe-jbd2" },
	{ "lttng-probe-kmem" },
	{ "lttng-probe-kvm" },
	{ "lttng-probe-kvm-x86" },
	{ "lttng-probe-kvm-x86-mmu" },
	{ "lttng-probe-lock" },
	{ "lttng-probe-module" },
	{ "lttng-probe-napi" },
	{ "lttng-probe-net" },
	{ "lttng-probe-power" },
	{ "lttng-probe-printk" },
	{ "lttng-probe-random" },
	{ "lttng-probe-rcu" },
	{ "lttng-probe-regmap" },
	{ "lttng-probe-regulator" },
	{ "lttng-probe-rpm" },
	{ "lttng-probe-sched" },
	{ "lttng-probe-scsi" },
	{ "lttng-probe-signal" },
	{ "lttng-probe-skb" },
	{ "lttng-probe-sock" },
	{ "lttng-probe-statedump" },
	{ "lttng-probe-sunrpc" },
	{ "lttng-probe-timer" },
	{ "lttng-probe-udp" },
	{ "lttng-probe-vmscan" },
	{ "lttng-probe-v4l2" },
	{ "lttng-probe-workqueue" },
	{ "lttng-probe-writeback" },
};

/* dynamic probe modules list */
static struct kern_modules_param *probes;
static int nr_probes;
static int probes_capacity;

static void modprobe_remove_lttng(const struct kern_modules_param *modules,
		int entries, int required)
{
	int ret = 0, i;
	char modprobe[256];

	for (i = entries - 1; i >= 0; i--) {
		ret = snprintf(modprobe, sizeof(modprobe),
				"/sbin/modprobe -r -q %s",
				modules[i].name);
		if (ret < 0) {
			PERROR("snprintf modprobe -r");
			return;
		}
		modprobe[sizeof(modprobe) - 1] = '\0';
		ret = system(modprobe);
		if (ret == -1) {
			ERR("Unable to launch modprobe -r for module %s",
					modules[i].name);
		} else if (required && WEXITSTATUS(ret) != 0) {
			ERR("Unable to remove module %s",
					modules[i].name);
		} else {
			DBG("Modprobe removal successful %s",
					modules[i].name);
		}
	}
}

/*
 * Remove control kernel module(s) in reverse load order.
 */
void modprobe_remove_lttng_control(void)
{
	modprobe_remove_lttng(kern_modules_control_opt,
			      ARRAY_SIZE(kern_modules_control_opt),
			      LTTNG_MOD_OPTIONAL);
	modprobe_remove_lttng(kern_modules_control_core,
			      ARRAY_SIZE(kern_modules_control_core),
			      LTTNG_MOD_REQUIRED);
}

static void free_probes(void)
{
	int i;

	if (!probes) {
		return;
	}
	for (i = 0; i < nr_probes; ++i) {
		free(probes[i].name);
	}
	free(probes);
	probes = NULL;
	nr_probes = 0;
}

/*
 * Remove data kernel modules in reverse load order.
 */
void modprobe_remove_lttng_data(void)
{
	if (!probes) {
		return;
	}
	modprobe_remove_lttng(probes, nr_probes, LTTNG_MOD_OPTIONAL);
	free_probes();
}

/*
 * Remove all kernel modules in reverse order.
 */
void modprobe_remove_lttng_all(void)
{
	modprobe_remove_lttng_data();
	modprobe_remove_lttng_control();
}

#if HAVE_KMOD
#include <libkmod.h>
static void log_kmod(void *data, int priority, const char *file, int line,
		const char *fn, const char *format, va_list args)
{
	char *str;

	if (vasprintf(&str, format, args) < 0) {
		return;
	}

	DBG("libkmod: %s", str);
	free(str);
}
static int modprobe_lttng(struct kern_modules_param *modules,
		int entries, int required)
{
	int ret = 0, i;
	struct kmod_ctx *ctx;

	ctx = kmod_new(NULL, NULL);
	if (!ctx) {
		PERROR("Unable to create kmod library context");
		ret = -ENOMEM;
		goto error;
	}

	kmod_set_log_fn(ctx, log_kmod, NULL);
	kmod_load_resources(ctx);

	for (i = 0; i < entries; i++) {
		struct kmod_module *mod = NULL;

		ret = kmod_module_new_from_name(ctx, modules[i].name, &mod);
		if (ret < 0) {
			PERROR("Failed to create kmod module for %s", modules[i].name);
			goto error;
		}

		ret = kmod_module_probe_insert_module(mod, KMOD_PROBE_IGNORE_LOADED,
				NULL, NULL, NULL, NULL);
		if (ret < 0) {
			if (required) {
				ERR("Unable to load required module %s",
						modules[i].name);
				goto error;
			} else {
				DBG("Unable to load optional module %s; continuing",
						modules[i].name);
				ret = 0;
			}
		} else {
			DBG("Modprobe successfully %s", modules[i].name);
		}

		kmod_module_unref(mod);
	}

error:
	if (ctx) {
		kmod_unref(ctx);
	}
	return ret;
}

#else /* HAVE_KMOD */

static int modprobe_lttng(struct kern_modules_param *modules,
		int entries, int required)
{
	int ret = 0, i;
	char modprobe[256];

	for (i = 0; i < entries; i++) {
		ret = snprintf(modprobe, sizeof(modprobe),
				"/sbin/modprobe %s%s",
				required ? "" : "-q ",
				modules[i].name);
		if (ret < 0) {
			PERROR("snprintf modprobe");
			goto error;
		}
		modprobe[sizeof(modprobe) - 1] = '\0';
		ret = system(modprobe);
		if (ret == -1) {
			if (required) {
				ERR("Unable to launch modprobe for required module %s",
						modules[i].name);
				goto error;
			} else {
				DBG("Unable to launch modprobe for optional module %s; continuing",
						modules[i].name);
				ret = 0;
			}
		} else if (WEXITSTATUS(ret) != 0) {
			if (required) {
				ERR("Unable to load required module %s",
						modules[i].name);
				goto error;
			} else {
				DBG("Unable to load optional module %s; continuing",
						modules[i].name);
				ret = 0;
			}
		} else {
			DBG("Modprobe successfully %s", modules[i].name);
		}
	}

error:
	return ret;
}

#endif /* HAVE_KMOD */

/*
 * Load control kernel module(s).
 */
int modprobe_lttng_control(void)
{
	int ret;

	ret = modprobe_lttng(kern_modules_control_core,
			     ARRAY_SIZE(kern_modules_control_core),
			     LTTNG_MOD_REQUIRED);
	if (ret != 0)
		return ret;
	ret = modprobe_lttng(kern_modules_control_opt,
			     ARRAY_SIZE(kern_modules_control_opt),
			     LTTNG_MOD_OPTIONAL);
	return ret;
}

/**
 * Grow global list of probes (double capacity or set it to 1 if
 * currently 0 and copy existing data).
 */
static int grow_probes(void)
{
	int i;
	struct kern_modules_param *tmp_probes;

	/* Initialize capacity to 1 if 0. */
	if (probes_capacity == 0) {
		probes = zmalloc(sizeof(*probes));
		if (!probes) {
			PERROR("malloc probe list");
			return -ENOMEM;
		}

		probes_capacity = 1;
		return 0;
	}

	/* Double size. */
	probes_capacity *= 2;

	tmp_probes = zmalloc(sizeof(*tmp_probes) * probes_capacity);
	if (!tmp_probes) {
		PERROR("malloc probe list");
		return -ENOMEM;
	}

	for (i = 0; i < nr_probes; ++i) {
		/* Move name pointer. */
		tmp_probes[i].name = probes[i].name;
	}

	/* Replace probes with larger copy. */
	free(probes);
	probes = tmp_probes;

	return 0;
}

/*
 * Appends a comma-separated list of probes to the global list
 * of probes.
 */
static int append_list_to_probes(const char *list)
{
	char *next;
	int ret;
	char *tmp_list, *cur_list;

	assert(list);

	cur_list = tmp_list = strdup(list);
	if (!tmp_list) {
		PERROR("strdup temp list");
		return -ENOMEM;
	}

	for (;;) {
		size_t name_len;
		struct kern_modules_param *cur_mod;

		next = strtok(cur_list, ",");
		if (!next) {
			break;
		}
		cur_list = NULL;

		/* filter leading spaces */
		while (*next == ' ') {
			next++;
		}

		if (probes_capacity <= nr_probes) {
			ret = grow_probes();
			if (ret) {
				goto error;
			}
		}

		/* Length 13 is "lttng-probe-" + \0 */
		name_len = strlen(next) + 13;

		cur_mod = &probes[nr_probes];
		cur_mod->name = zmalloc(name_len);
		if (!cur_mod->name) {
			PERROR("malloc probe list");
			ret = -ENOMEM;
			goto error;
		}

		ret = snprintf(cur_mod->name, name_len, "lttng-probe-%s", next);
		if (ret < 0) {
			PERROR("snprintf modprobe name");
			ret = -ENOMEM;
			goto error;
		}

		nr_probes++;
	}

	free(tmp_list);
	return 0;

error:
	free(tmp_list);
	free_probes();
	return ret;
}

/*
 * Load data kernel module(s).
 */
int modprobe_lttng_data(void)
{
	int ret, i;
	char *list;

	/*
	 * Base probes: either from command line option, environment
	 * variable or default list.
	 */
	if (kmod_probes_list) {
		list = kmod_probes_list;
	} else {
		list = utils_get_kmod_probes_list();
	}

	if (list) {
		/* User-specified probes. */
		ret = append_list_to_probes(list);
		if (ret) {
			return ret;
		}
	} else {
		/* Default probes. */
		int def_len = ARRAY_SIZE(kern_modules_probes_default);

		probes = zmalloc(sizeof(*probes) * def_len);
		if (!probes) {
			PERROR("malloc probe list");
			return -ENOMEM;
		}

		nr_probes = probes_capacity = def_len;

		for (i = 0; i < def_len; ++i) {
			char* name = strdup(kern_modules_probes_default[i].name);

			if (!name) {
				PERROR("strdup probe item");
				ret = -ENOMEM;
				goto error;
			}

			probes[i].name = name;
		}
	}

	/*
	 * Extra modules? Append them to current probes list.
	 */
	if (kmod_extra_probes_list) {
		list = kmod_extra_probes_list;
	} else {
		list = utils_get_extra_kmod_probes_list();
	}

	if (list) {
		ret = append_list_to_probes(list);
		if (ret) {
			goto error;
		}
	}

	/*
	 * Load probes modules now.
	 */
	ret = modprobe_lttng(probes, nr_probes, LTTNG_MOD_OPTIONAL);
	if (ret) {
		goto error;
	}
	return ret;

error:
	free_probes();
	return ret;
}
