/*
 * Copyright (C) 2011 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2014 Jan Glauber <jan.glauber@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

/**
 * @file modprobe.c
 *
 * @brief modprobe related functions.
 *
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
#include "lttng-sessiond.h"

/* LTTng kernel tracer mandatory core modules list */
struct kern_modules_param kern_modules_control_core[] = {
	{
		.name = (char *) "lttng-ring-buffer-client-discard",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_REQUIRED,
	},
	{
		.name = (char *) "lttng-ring-buffer-client-overwrite",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_REQUIRED,
	},
	{
		.name = (char *) "lttng-ring-buffer-metadata-client",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_REQUIRED,
	},
	{
		.name = (char *) "lttng-ring-buffer-client-mmap-discard",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_REQUIRED,
	},
	{
		.name = (char *) "lttng-ring-buffer-client-mmap-overwrite",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_REQUIRED,
	},
	{
		.name = (char *) "lttng-ring-buffer-metadata-mmap-client",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_REQUIRED,
	},
	{
		.name = (char *) "lttng-ring-buffer-event_notifier-client",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-counter-client-percpu-64-modular",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-counter-client-percpu-32-modular",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
};

/* LTTng kerneltracer probe modules list */
struct kern_modules_param kern_modules_probes_default[] = {
	{
		.name = (char *) "lttng-probe-asoc",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-block",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-btrfs",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-compaction",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-ext3",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-ext4",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-gpio",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-i2c",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-irq",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-jbd",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-jbd2",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-kmem",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-kvm",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-kvm-x86",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-kvm-x86-mmu",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-lock",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-module",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-napi",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-net",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-power",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-preemptirq",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-printk",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-random",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-rcu",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-regmap",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-regulator",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-rpm",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-sched",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-scsi",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-signal",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-skb",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-sock",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-statedump",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-sunrpc",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-timer",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-udp",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-vmscan",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-v4l2",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-workqueue",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-writeback",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-x86-irq-vectors",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
	{
		.name = (char *) "lttng-probe-x86-exceptions",
		.load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL,
	},
};

/* dynamic probe modules list */
static struct kern_modules_param *probes;
static int nr_probes;
static int probes_capacity;

#if HAVE_KMOD
#include <libkmod.h>

/**
 * @brief Logging function for libkmod integration.
 */
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

/**
 * @brief Setup the libkmod context.
 *
 * Create the context, add a custom logging function and preload the
 * ressources for faster operation.
 *
 * @returns	\c 0 on success
 * 		\c < 0 on error
 */
static int setup_kmod_ctx(struct kmod_ctx **ctx)
{
	int ret = 0;

	*ctx = kmod_new(NULL, NULL);
	if (!ctx) {
		PERROR("Unable to create kmod library context");
		ret = -ENOMEM;
		goto error;
	}

	kmod_set_log_fn(*ctx, log_kmod, NULL);
	ret = kmod_load_resources(*ctx);
	if (ret < 0) {
		ERR("Failed to load kmod library resources");
		goto error;
	}

error:
	return ret;
}

/**
 * @brief Loads the kernel modules in \p modules
 *
 * @param modules	List of modules to load
 * @param entries	Number of modules in the list
 *
 * If the modules are required, we will return with error after the
 * first failed module load, otherwise we continue loading.
 *
 * @returns		\c 0 on success
 * 			\c < 0 on error
 */
static int modprobe_lttng(struct kern_modules_param *modules,
		int entries)
{
	int ret = 0, i;
	struct kmod_ctx *ctx;

	ret = setup_kmod_ctx(&ctx);
	if (ret < 0) {
		goto error;
	}

	for (i = 0; i < entries; i++) {
		struct kmod_module *mod = NULL;

		ret = kmod_module_new_from_name(ctx, modules[i].name, &mod);
		if (ret < 0) {
			PERROR("Failed to create kmod module for %s", modules[i].name);
			goto error;
		}

		ret = kmod_module_probe_insert_module(mod, 0,
				NULL, NULL, NULL, NULL);
		if (ret == -EEXIST) {
			DBG("Module %s is already loaded", modules[i].name);
			ret = 0;
		} else if (ret < 0) {
			if (modules[i].load_policy == KERNEL_MODULE_PROPERTY_LOAD_POLICY_REQUIRED) {
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
			modules[i].loaded = true;
		}

		kmod_module_unref(mod);
	}

error:
	if (ctx) {
		kmod_unref(ctx);
	}
	return ret;
}

/**
 * @brief Recursively unload modules.
 *
 * This function implements the same modules unloading behavior as
 * 'modprobe -r' or rmmod, it will recursevily go trought the \p module
 * dependencies and unload modules with a refcount of 0.
 *
 * @param mod		The module to unload
 *
 * @returns		\c 0 on success
 * 			\c < 0 on error
 */
static int rmmod_recurse(struct kmod_module *mod) {
	int ret = 0;
	struct kmod_list *deps, *itr;

	if (kmod_module_get_initstate(mod) == KMOD_MODULE_BUILTIN) {
		DBG("Module %s is builtin", kmod_module_get_name(mod));
		return ret;
	}

	ret = kmod_module_remove_module(mod, 0);

	deps = kmod_module_get_dependencies(mod);
	if (deps != NULL) {
		kmod_list_foreach(itr, deps) {
			struct kmod_module *dep = kmod_module_get_module(itr);
			if (kmod_module_get_refcnt(dep) == 0) {
				DBG("Recursive remove module %s",
						kmod_module_get_name(dep));
				rmmod_recurse(dep);
			}
			kmod_module_unref(dep);
		}
		kmod_module_unref_list(deps);
	}

	return ret;
}

/**
 * @brief Unloads the kernel modules in \p modules
 *
 * @param modules	List of modules to unload
 * @param entries	Number of modules in the list
 *
 */
static void modprobe_remove_lttng(const struct kern_modules_param *modules,
		int entries)
{
	int ret = 0, i;
	struct kmod_ctx *ctx;

	ret = setup_kmod_ctx(&ctx);
	if (ret < 0) {
		goto error;
	}

	for (i = entries - 1; i >= 0; i--) {
		struct kmod_module *mod = NULL;

		if (!modules[i].loaded) {
			continue;
		}

		ret = kmod_module_new_from_name(ctx, modules[i].name, &mod);
		if (ret < 0) {
			PERROR("Failed to create kmod module for %s", modules[i].name);
			goto error;
		}

		ret = rmmod_recurse(mod);
		if (ret == -EEXIST) {
			DBG("Module %s is not in kernel.", modules[i].name);
		} else if (modules[i].load_policy == KERNEL_MODULE_PROPERTY_LOAD_POLICY_REQUIRED && ret < 0) {
			ERR("Unable to remove module %s", modules[i].name);
		} else {
			DBG("Modprobe removal successful %s",
				modules[i].name);
		}

		kmod_module_unref(mod);
	}

error:
	if (ctx) {
		kmod_unref(ctx);
	}
}

#else /* HAVE_KMOD */

static int modprobe_lttng(struct kern_modules_param *modules,
		int entries)
{
	int ret = 0, i;
	char modprobe[256];

	for (i = 0; i < entries; i++) {
		ret = snprintf(modprobe, sizeof(modprobe),
				"/sbin/modprobe %s%s",
				modules[i].load_policy == KERNEL_MODULE_PROPERTY_LOAD_POLICY_REQUIRED ? "" : "-q ",
				modules[i].name);
		if (ret < 0) {
			PERROR("snprintf modprobe");
			goto error;
		}
		modprobe[sizeof(modprobe) - 1] = '\0';
		ret = system(modprobe);
		if (ret == -1) {
			if (modules[i].load_policy == KERNEL_MODULE_PROPERTY_LOAD_POLICY_REQUIRED) {
				ERR("Unable to launch modprobe for required module %s",
						modules[i].name);
				goto error;
			} else {
				DBG("Unable to launch modprobe for optional module %s; continuing",
						modules[i].name);
				ret = 0;
			}
		} else if (WEXITSTATUS(ret) != 0) {
			if (modules[i].load_policy == KERNEL_MODULE_PROPERTY_LOAD_POLICY_REQUIRED) {
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
			modules[i].loaded = true;
		}
	}

error:
	return ret;
}

static void modprobe_remove_lttng(const struct kern_modules_param *modules,
		int entries)
{
	int ret = 0, i;
	char modprobe[256];

	for (i = entries - 1; i >= 0; i--) {
		if (!modules[i].loaded) {
			continue;
		}
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
			if (modules[i].load_policy == KERNEL_MODULE_PROPERTY_LOAD_POLICY_REQUIRED) {
				ERR("Unable to launch modprobe -r for required module %s",
						modules[i].name);
			} else {
				DBG("Unable to launch modprobe -r for optional module %s",
						modules[i].name);
			}
		} else if (WEXITSTATUS(ret) != 0) {
			if (modules[i].load_policy == KERNEL_MODULE_PROPERTY_LOAD_POLICY_REQUIRED) {
				ERR("Unable to remove required module %s",
						modules[i].name);
			} else {
				DBG("Unable to remove optional module %s",
						modules[i].name);
			}
		} else {
			DBG("Modprobe removal successful %s", modules[i].name);
		}
	}
}

#endif /* HAVE_KMOD */

/*
 * Remove control kernel module(s) in reverse load order.
 */
void modprobe_remove_lttng_control(void)
{
	modprobe_remove_lttng(kern_modules_control_core,
			ARRAY_SIZE(kern_modules_control_core));
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

	modprobe_remove_lttng(probes, nr_probes);
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

/*
 * Load control kernel module(s).
 */
int modprobe_lttng_control(void)
{
	return modprobe_lttng(kern_modules_control_core,
			ARRAY_SIZE(kern_modules_control_core));
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
		/* Ownership of 'name' field is transferred. */
		tmp_probes[i] = probes[i];
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
	char *tmp_list, *cur_list, *saveptr;

	assert(list);

	cur_list = tmp_list = strdup(list);
	if (!tmp_list) {
		PERROR("strdup temp list");
		return -ENOMEM;
	}

	for (;;) {
		size_t name_len;
		struct kern_modules_param *cur_mod;

		next = strtok_r(cur_list, ",", &saveptr);
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

		cur_mod->load_policy = KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL;

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
	list = config.kmod_probes_list.value;
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
			probes[i].load_policy = kern_modules_probes_default[i].load_policy;
		}
	}

	/*
	 * Extra modules? Append them to current probes list.
	 */
	list = config.kmod_extra_probes_list.value;
	if (list) {
		ret = append_list_to_probes(list);
		if (ret) {
			goto error;
		}
	}

	/*
	 * Load probes modules now.
	 */
	ret = modprobe_lttng(probes, nr_probes);
	if (ret) {
		goto error;
	}
	return ret;

error:
	free_probes();
	return ret;
}
