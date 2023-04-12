/*
 * Copyright (C) 2011 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _KERN_MODULES_H
#define _KERN_MODULES_H

/*
 * Compatible lttng-modules version.
 */
#define KERN_MODULES_PRE_MAJOR 1
#define KERN_MODULES_PRE_MINOR 9

#define KERN_MODULES_MAJOR 2
#define KERN_MODULES_MINOR 0

enum kernel_module_property_load_policy {
	KERNEL_MODULE_PROPERTY_LOAD_POLICY_REQUIRED = 0,
	KERNEL_MODULE_PROPERTY_LOAD_POLICY_OPTIONAL = 1,
};

struct kern_modules_param {
	char *name;
	enum kernel_module_property_load_policy load_policy;
	bool loaded;
};

#endif /* _KERN_MODULES_H */
