/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "lttng/lttng-error.h"
#include <assert.h>
#include <common/compat/string.h>
#include <common/error.h>
#include <common/macros.h>
#include <common/payload.h>
#include <common/payload-view.h>
#include <fcntl.h>
#include <lttng/constant.h>
#include <lttng/userspace-probe-internal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/unistd.h>

static
int lttng_userspace_probe_location_function_set_binary_fd_handle(
		struct lttng_userspace_probe_location *location,
		struct fd_handle *binary_fd_handle);

static
int lttng_userspace_probe_location_tracepoint_set_binary_fd_handle(
		struct lttng_userspace_probe_location *location,
		struct fd_handle *binary_fd_handle);

enum lttng_userspace_probe_location_lookup_method_type
lttng_userspace_probe_location_lookup_method_get_type(
		const struct lttng_userspace_probe_location_lookup_method *lookup_method)
{
	return lookup_method ? lookup_method->type :
		LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_UNKNOWN;
}

void lttng_userspace_probe_location_lookup_method_destroy(
		struct lttng_userspace_probe_location_lookup_method *lookup_method)
{
	if (!lookup_method){
		return;
	}

	free(lookup_method);
}

struct lttng_userspace_probe_location_lookup_method *
lttng_userspace_probe_location_lookup_method_function_elf_create(void)
{
	struct lttng_userspace_probe_location_lookup_method *ret = NULL;
	struct lttng_userspace_probe_location_lookup_method_elf *elf_method;

	elf_method = zmalloc(sizeof(*elf_method));
	if (!elf_method) {
		PERROR("zmalloc");
		goto end;
	}

	ret = &elf_method->parent;
	ret->type = LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF;
end:
	return ret;
}

struct lttng_userspace_probe_location_lookup_method *
lttng_userspace_probe_location_lookup_method_tracepoint_sdt_create(void)
{
	struct lttng_userspace_probe_location_lookup_method *ret = NULL;
	struct lttng_userspace_probe_location_lookup_method_sdt *sdt_method;

	sdt_method = zmalloc(sizeof(*sdt_method));
	if (!sdt_method) {
		PERROR("zmalloc");
		goto end;
	}

	ret = &sdt_method->parent;
	ret->type = LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT;
end:
	return ret;
}

enum lttng_userspace_probe_location_type lttng_userspace_probe_location_get_type(
		const struct lttng_userspace_probe_location *location)
{
	return location ? location->type :
		LTTNG_USERSPACE_PROBE_LOCATION_TYPE_UNKNOWN;
}

static
void lttng_userspace_probe_location_function_destroy(
		struct lttng_userspace_probe_location *location)
{
	struct lttng_userspace_probe_location_function *location_function = NULL;

	assert(location);

	location_function = container_of(location,
			struct lttng_userspace_probe_location_function, parent);

	assert(location_function);

	free(location_function->function_name);
	free(location_function->binary_path);
	fd_handle_put(location_function->binary_fd_handle);
	free(location);
}

static
void lttng_userspace_probe_location_tracepoint_destroy(
		struct lttng_userspace_probe_location *location)
{
	struct lttng_userspace_probe_location_tracepoint *location_tracepoint = NULL;

	assert(location);

	location_tracepoint = container_of(location,
			struct lttng_userspace_probe_location_tracepoint,
			parent);

	assert(location_tracepoint);

	free(location_tracepoint->probe_name);
	free(location_tracepoint->provider_name);
	free(location_tracepoint->binary_path);
	fd_handle_put(location_tracepoint->binary_fd_handle);
	free(location);
}

void lttng_userspace_probe_location_destroy(
		struct lttng_userspace_probe_location *location)
{
	if (!location) {
		return;
	}

	lttng_userspace_probe_location_lookup_method_destroy(
			location->lookup_method);

	switch (location->type) {
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION:
		lttng_userspace_probe_location_function_destroy(location);
		break;
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT:
		lttng_userspace_probe_location_tracepoint_destroy(location);
		break;
	default:
		abort();
	}
}

/* Compare two file descriptors based on their inode and device numbers. */
static bool fd_is_equal(int a, int b)
{
	int ret;
	bool is_equal = false;
	struct stat a_stat, b_stat;

	if (a < 0 && b >= 0) {
		goto end;
	}

	if (b < 0 && a >= 0) {
		goto end;
	}

	if (a < 0 && b < 0) {
		if (a == -1 && b == -1) {
			is_equal = true;
			goto end;
		}

		/* Invalid state, abort. */
		abort();
	}

	/* Both are valid file descriptors. */
	ret = fstat(a, &a_stat);
	if (ret) {
		PERROR("Failed to fstat userspace probe location binary fd %d",
				a);
		goto end;
	}

	ret = fstat(b, &b_stat);
	if (ret) {
		PERROR("Failed to fstat userspace probe location binary fd %d",
				b);
		goto end;
	}

	is_equal = (a_stat.st_ino == b_stat.st_ino) &&
			(a_stat.st_dev == b_stat.st_dev);

end:
	return is_equal;
}

static bool lttng_userspace_probe_location_function_is_equal(
		const struct lttng_userspace_probe_location *_a,
		const struct lttng_userspace_probe_location *_b)
{
	bool is_equal = false;
	struct lttng_userspace_probe_location_function *a, *b;

	a = container_of(_a, struct lttng_userspace_probe_location_function,
			parent);
	b = container_of(_b, struct lttng_userspace_probe_location_function,
			parent);

	if (a->instrumentation_type != b->instrumentation_type) {
		goto end;
	}

	assert(a->function_name);
	assert(b->function_name);
	if (strcmp(a->function_name, b->function_name)) {
		goto end;
	}

	assert(a->binary_path);
	assert(b->binary_path);
	if (strcmp(a->binary_path, b->binary_path)) {
		goto end;
	}

	is_equal = fd_is_equal(a->binary_fd_handle ? fd_handle_get_fd(a->binary_fd_handle) : -1,
			b->binary_fd_handle ? fd_handle_get_fd(b->binary_fd_handle) : -1);
end:
	return is_equal;
}

static struct lttng_userspace_probe_location *
lttng_userspace_probe_location_function_create_no_check(const char *binary_path,
		const char *function_name,
		struct lttng_userspace_probe_location_lookup_method *lookup_method,
		bool open_binary)
{
	int binary_fd = -1;
	struct fd_handle *binary_fd_handle = NULL;
	char *function_name_copy = NULL, *binary_path_copy = NULL;
	struct lttng_userspace_probe_location *ret = NULL;
	struct lttng_userspace_probe_location_function *location;

	if (open_binary) {
		binary_fd = open(binary_path, O_RDONLY);
		if (binary_fd < 0) {
			PERROR("Error opening the binary");
			goto error;
		}

		binary_fd_handle = fd_handle_create(binary_fd);
		if (!binary_fd) {
			goto error;
		}

		/* Ownership transferred to fd_handle. */
		binary_fd = -1;
	}

	function_name_copy = lttng_strndup(function_name, LTTNG_SYMBOL_NAME_LEN);
	if (!function_name_copy) {
		PERROR("Error duplicating the function name");
		goto error;
	}

	binary_path_copy = lttng_strndup(binary_path, LTTNG_PATH_MAX);
	if (!binary_path_copy) {
		PERROR("Error duplicating the function name");
		goto error;
	}

	location = zmalloc(sizeof(*location));
	if (!location) {
		PERROR("Error allocating userspace probe location");
		goto error;
	}

	location->function_name = function_name_copy;
	location->binary_path = binary_path_copy;
	location->binary_fd_handle = binary_fd_handle;
	binary_fd_handle = NULL;
	location->instrumentation_type =
			LTTNG_USERSPACE_PROBE_LOCATION_FUNCTION_INSTRUMENTATION_TYPE_ENTRY;

	ret = &location->parent;
	ret->lookup_method = lookup_method;
	ret->type = LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION;
	ret->equal = lttng_userspace_probe_location_function_is_equal;
	goto end;

error:
	free(function_name_copy);
	free(binary_path_copy);
	if (binary_fd >= 0) {
		if (close(binary_fd)) {
			PERROR("Error closing binary fd in error path");
		}
	}
	fd_handle_put(binary_fd_handle);
end:
	return ret;
}

static bool lttng_userspace_probe_location_tracepoint_is_equal(
		const struct lttng_userspace_probe_location *_a,
		const struct lttng_userspace_probe_location *_b)
{
	bool is_equal = false;
	struct lttng_userspace_probe_location_tracepoint *a, *b;

	a = container_of(_a, struct lttng_userspace_probe_location_tracepoint,
			parent);
	b = container_of(_b, struct lttng_userspace_probe_location_tracepoint,
			parent);

	assert(a->probe_name);
	assert(b->probe_name);
	if (strcmp(a->probe_name, b->probe_name)) {
		goto end;
	}

	assert(a->provider_name);
	assert(b->provider_name);
	if (strcmp(a->provider_name, b->provider_name)) {
		goto end;
	}

	assert(a->binary_path);
	assert(b->binary_path);
	if (strcmp(a->binary_path, b->binary_path)) {
		goto end;
	}

	is_equal = fd_is_equal(a->binary_fd_handle ? fd_handle_get_fd(a->binary_fd_handle) : -1,
			b->binary_fd_handle ? fd_handle_get_fd(b->binary_fd_handle) : -1);

end:
	return is_equal;
}

static struct lttng_userspace_probe_location *
lttng_userspace_probe_location_tracepoint_create_no_check(const char *binary_path,
		const char *provider_name, const char *probe_name,
		struct lttng_userspace_probe_location_lookup_method *lookup_method,
		bool open_binary)
{
	int binary_fd = -1;
	struct fd_handle *binary_fd_handle = NULL;
	char *probe_name_copy = NULL;
	char *provider_name_copy = NULL;
	char *binary_path_copy = NULL;
	struct lttng_userspace_probe_location *ret = NULL;
	struct lttng_userspace_probe_location_tracepoint *location;

	if (open_binary) {
		binary_fd = open(binary_path, O_RDONLY);
		if (binary_fd < 0) {
			PERROR("open");
			goto error;
		}

		binary_fd_handle = fd_handle_create(binary_fd);
		if (!binary_fd) {
			goto error;
		}

		/* Ownership transferred to fd_handle. */
		binary_fd = -1;
	}

	probe_name_copy = lttng_strndup(probe_name, LTTNG_SYMBOL_NAME_LEN);
	if (!probe_name_copy) {
		PERROR("lttng_strndup");
		goto error;
	}

	provider_name_copy = lttng_strndup(provider_name, LTTNG_SYMBOL_NAME_LEN);
	if (!provider_name_copy) {
		PERROR("lttng_strndup");
		goto error;
	}

	binary_path_copy = lttng_strndup(binary_path, LTTNG_PATH_MAX);
	if (!binary_path_copy) {
		PERROR("lttng_strndup");
		goto error;
	}

	location = zmalloc(sizeof(*location));
	if (!location) {
		PERROR("zmalloc");
		goto error;
	}

	location->probe_name = probe_name_copy;
	location->provider_name = provider_name_copy;
	location->binary_path = binary_path_copy;
	location->binary_fd_handle = binary_fd_handle;
	binary_fd_handle = NULL;

	ret = &location->parent;
	ret->lookup_method = lookup_method;
	ret->type = LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT;
	ret->equal = lttng_userspace_probe_location_tracepoint_is_equal;
	goto end;

error:
	free(probe_name_copy);
	free(provider_name_copy);
	free(binary_path_copy);
	if (binary_fd >= 0) {
		if (close(binary_fd)) {
			PERROR("Error closing binary fd in error path");
		}
	}
	fd_handle_put(binary_fd_handle);
end:
	return ret;
}

struct lttng_userspace_probe_location *
lttng_userspace_probe_location_function_create(const char *binary_path,
		const char *function_name,
		struct lttng_userspace_probe_location_lookup_method *lookup_method)
{
	struct lttng_userspace_probe_location *ret = NULL;

	if (!binary_path || !function_name) {
		ERR("Invalid argument(s) passed to '%s'", __FUNCTION__);
		goto end;
	}

	switch (lttng_userspace_probe_location_lookup_method_get_type(
			lookup_method)) {
	case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_DEFAULT:
	case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF:
		break;
	default:
		/* Invalid probe location lookup method. */
		goto end;
	}

	ret = lttng_userspace_probe_location_function_create_no_check(
			binary_path, function_name, lookup_method, true);
end:
	return ret;
}

struct lttng_userspace_probe_location *
lttng_userspace_probe_location_tracepoint_create(const char *binary_path,
		const char *provider_name, const char *probe_name,
		struct lttng_userspace_probe_location_lookup_method *lookup_method)
{
	struct lttng_userspace_probe_location *ret = NULL;

	if (!binary_path || !probe_name || !provider_name) {
		ERR("Invalid argument(s) passed to '%s'", __FUNCTION__);
		goto end;
	}

	switch (lttng_userspace_probe_location_lookup_method_get_type(
			lookup_method)) {
	case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT:
		break;
	default:
		/* Invalid probe location lookup method. */
		goto end;
	}

	ret = lttng_userspace_probe_location_tracepoint_create_no_check(
			binary_path, provider_name, probe_name, lookup_method, true);
end:
	return ret;
}

static struct lttng_userspace_probe_location_lookup_method *
lttng_userspace_probe_location_lookup_method_function_elf_copy(
		const struct lttng_userspace_probe_location_lookup_method *lookup_method)
{
	struct lttng_userspace_probe_location_lookup_method *parent = NULL;
	struct lttng_userspace_probe_location_lookup_method_elf *elf_method;

	assert(lookup_method);
	assert(lookup_method->type ==
			LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF);

	elf_method = zmalloc(sizeof(*elf_method));
	if (!elf_method) {
		PERROR("Error allocating ELF userspace probe lookup method");
		goto error;
	}

	elf_method->parent.type = lookup_method->type;
	parent = &elf_method->parent;

	goto end;
error:
	parent = NULL;
end:
	return parent;
}

static struct lttng_userspace_probe_location_lookup_method *
lttng_userspace_probe_location_lookup_method_tracepoint_sdt_copy(
		struct lttng_userspace_probe_location_lookup_method *lookup_method)
{
	struct lttng_userspace_probe_location_lookup_method *parent = NULL;
	struct lttng_userspace_probe_location_lookup_method_sdt *sdt_method;

	assert(lookup_method);
	assert(lookup_method->type ==
			LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT);

	sdt_method = zmalloc(sizeof(*sdt_method));
	if (!sdt_method) {
		PERROR("zmalloc");
		goto error;
	}

	sdt_method->parent.type = lookup_method->type;
	parent = &sdt_method->parent;

	goto end;

error:
	parent = NULL;
end:
	return parent;
}

static struct lttng_userspace_probe_location *
lttng_userspace_probe_location_function_copy(
		const struct lttng_userspace_probe_location *location)
{
	enum lttng_userspace_probe_location_lookup_method_type lookup_type;
	struct lttng_userspace_probe_location *new_location = NULL;
	struct lttng_userspace_probe_location_lookup_method *lookup_method = NULL;
	const char *binary_path = NULL;
	const char *function_name = NULL;
	struct lttng_userspace_probe_location_function *function_location;

	assert(location);
	assert(location->type == LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION);
	function_location = container_of(
			location, typeof(*function_location), parent);

	 /* Get probe location fields */
	binary_path = lttng_userspace_probe_location_function_get_binary_path(location);
	if (!binary_path) {
		ERR("Userspace probe binary path is NULL");
		goto error;
	}

	function_name = lttng_userspace_probe_location_function_get_function_name(location);
	if (!function_name) {
		ERR("Userspace probe function name is NULL");
		goto error;
	}

	/*
	 * Duplicate probe location method fields
	 */
	lookup_type = lttng_userspace_probe_location_lookup_method_get_type(
			location->lookup_method);
	switch (lookup_type) {
	case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF:
		lookup_method =
			lttng_userspace_probe_location_lookup_method_function_elf_copy(
					location->lookup_method);
		if (!lookup_method) {
			goto error;
		}
		break;
	default:
		/* Invalid probe location lookup method. */
		goto error;
	}

	/* Create the probe_location */
	new_location = lttng_userspace_probe_location_function_create_no_check(
			binary_path, function_name, lookup_method, false);
	if (!new_location) {
		goto destroy_lookup_method;
	}

	/* Set the duplicated fd to the new probe_location */
	if (lttng_userspace_probe_location_function_set_binary_fd_handle(new_location,
			function_location->binary_fd_handle) < 0) {
		goto destroy_probe_location;
	}

	goto end;

destroy_probe_location:
	lttng_userspace_probe_location_destroy(new_location);
destroy_lookup_method:
	lttng_userspace_probe_location_lookup_method_destroy(lookup_method);
error:
	new_location = NULL;
end:
	return new_location;
}

static struct lttng_userspace_probe_location *
lttng_userspace_probe_location_tracepoint_copy(
		const struct lttng_userspace_probe_location *location)
{
	enum lttng_userspace_probe_location_lookup_method_type lookup_type;
	struct lttng_userspace_probe_location *new_location = NULL;
	struct lttng_userspace_probe_location_lookup_method *lookup_method = NULL;
	const char *binary_path = NULL;
	const char *probe_name = NULL;
	const char *provider_name = NULL;
	struct lttng_userspace_probe_location_tracepoint *tracepoint_location;

	assert(location);
	assert(location->type == LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT);
	tracepoint_location = container_of(
			location, typeof(*tracepoint_location), parent);

	/* Get probe location fields */
	binary_path = lttng_userspace_probe_location_tracepoint_get_binary_path(location);
	if (!binary_path) {
		ERR("Userspace probe binary path is NULL");
		goto error;
	}

	probe_name = lttng_userspace_probe_location_tracepoint_get_probe_name(location);
	if (!probe_name) {
		ERR("Userspace probe probe name is NULL");
		goto error;
	}

	provider_name = lttng_userspace_probe_location_tracepoint_get_provider_name(location);
	if (!provider_name) {
		ERR("Userspace probe provider name is NULL");
		goto error;
	}

	/*
	 * Duplicate probe location method fields
	 */
	lookup_type = lttng_userspace_probe_location_lookup_method_get_type(
			location->lookup_method);
	switch (lookup_type) {
	case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT:
		lookup_method =
			lttng_userspace_probe_location_lookup_method_tracepoint_sdt_copy(
					location->lookup_method);
		if (!lookup_method) {
			goto error;
		}
		break;
	default:
		/* Invalid probe location lookup method. */
		goto error;
	}

	/* Create the probe_location */
	new_location = lttng_userspace_probe_location_tracepoint_create_no_check(
			binary_path, provider_name, probe_name, lookup_method, false);
	if (!new_location) {
		goto destroy_lookup_method;
	}

	/* Set the duplicated fd to the new probe_location */
	if (lttng_userspace_probe_location_tracepoint_set_binary_fd_handle(new_location,
			tracepoint_location->binary_fd_handle) < 0) {
		goto destroy_probe_location;
	}

	goto end;

destroy_probe_location:
	lttng_userspace_probe_location_destroy(new_location);
destroy_lookup_method:
	lttng_userspace_probe_location_lookup_method_destroy(lookup_method);
error:
	new_location = NULL;
end:
	return new_location;
}

const char *lttng_userspace_probe_location_function_get_binary_path(
		const struct lttng_userspace_probe_location *location)
{
	const char *ret = NULL;
	struct lttng_userspace_probe_location_function *function_location;

	if (!location || lttng_userspace_probe_location_get_type(location) !=
			LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION) {
		ERR("Invalid argument(s) passed to '%s'", __FUNCTION__);
		goto end;
	}

	function_location = container_of(location,
		struct lttng_userspace_probe_location_function,
			parent);
	ret = function_location->binary_path;
end:
	return ret;
}

const char *lttng_userspace_probe_location_tracepoint_get_binary_path(
		const struct lttng_userspace_probe_location *location)
{
	const char *ret = NULL;
	struct lttng_userspace_probe_location_tracepoint *tracepoint_location;

	if (!location || lttng_userspace_probe_location_get_type(location) !=
			LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT) {
		ERR("Invalid argument(s) passed to '%s'", __FUNCTION__);
		goto end;
	}

	tracepoint_location = container_of(location,
		struct lttng_userspace_probe_location_tracepoint,
			parent);
	ret = tracepoint_location->binary_path;
end:
	return ret;
}

const char *lttng_userspace_probe_location_function_get_function_name(
		const struct lttng_userspace_probe_location *location)
{
	const char *ret = NULL;
	struct lttng_userspace_probe_location_function *function_location;

	if (!location || lttng_userspace_probe_location_get_type(location) !=
			LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION) {
		ERR("Invalid argument(s) passed to '%s'", __FUNCTION__);
		goto end;
	}

	function_location = container_of(location,
		struct lttng_userspace_probe_location_function, parent);
	ret = function_location->function_name;
end:
	return ret;
}

const char *lttng_userspace_probe_location_tracepoint_get_probe_name(
		const struct lttng_userspace_probe_location *location)
{
	const char *ret = NULL;
	struct lttng_userspace_probe_location_tracepoint *tracepoint_location;

	if (!location || lttng_userspace_probe_location_get_type(location) !=
			LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT) {
		ERR("Invalid argument(s) passed to '%s'", __FUNCTION__);
		goto end;
	}

	tracepoint_location = container_of(location,
		struct lttng_userspace_probe_location_tracepoint, parent);
	ret = tracepoint_location->probe_name;
end:
	return ret;
}

const char *lttng_userspace_probe_location_tracepoint_get_provider_name(
		const struct lttng_userspace_probe_location *location)
{
	const char *ret = NULL;
	struct lttng_userspace_probe_location_tracepoint *tracepoint_location;

	if (!location || lttng_userspace_probe_location_get_type(location) !=
			LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT) {
		ERR("Invalid argument(s) passed to '%s'", __FUNCTION__);
		goto end;
	}

	tracepoint_location = container_of(location,
		struct lttng_userspace_probe_location_tracepoint, parent);
	ret = tracepoint_location->provider_name;
end:
	return ret;
}

int lttng_userspace_probe_location_function_get_binary_fd(
		const struct lttng_userspace_probe_location *location)
{
	int ret = -1;
	struct lttng_userspace_probe_location_function *function_location;

	if (!location || lttng_userspace_probe_location_get_type(location) !=
			LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION) {
		ERR("Invalid argument(s) passed to '%s'", __FUNCTION__);
		goto end;
	}

	function_location = container_of(location,
		struct lttng_userspace_probe_location_function, parent);
	ret = function_location->binary_fd_handle ?
			fd_handle_get_fd(function_location->binary_fd_handle) : -1;
end:
	return ret;
}

enum lttng_userspace_probe_location_function_instrumentation_type
lttng_userspace_probe_location_function_get_instrumentation_type(
		const struct lttng_userspace_probe_location *location)
{
	enum lttng_userspace_probe_location_function_instrumentation_type type;
	struct lttng_userspace_probe_location_function *function_location;

	if (!location || lttng_userspace_probe_location_get_type(location) !=
			LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION) {
		ERR("Invalid argument(s) passed to '%s'", __FUNCTION__);
		type = LTTNG_USERSPACE_PROBE_LOCATION_FUNCTION_INSTRUMENTATION_TYPE_UNKNOWN;
		goto end;
	}

	function_location = container_of(location,
		struct lttng_userspace_probe_location_function, parent);
	type = function_location->instrumentation_type;
end:
	return type;
}

enum lttng_userspace_probe_location_status
lttng_userspace_probe_location_function_set_instrumentation_type(
		const struct lttng_userspace_probe_location *location,
		enum lttng_userspace_probe_location_function_instrumentation_type instrumentation_type)
{
	enum lttng_userspace_probe_location_status status =
			LTTNG_USERSPACE_PROBE_LOCATION_STATUS_OK;
	struct lttng_userspace_probe_location_function *function_location;

	if (!location || lttng_userspace_probe_location_get_type(location) !=
			LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION ||
			instrumentation_type !=
			LTTNG_USERSPACE_PROBE_LOCATION_FUNCTION_INSTRUMENTATION_TYPE_ENTRY) {
		ERR("Invalid argument(s) passed to '%s'", __FUNCTION__);
		status = LTTNG_USERSPACE_PROBE_LOCATION_STATUS_INVALID;
		goto end;
	}

	function_location = container_of(location,
		struct lttng_userspace_probe_location_function, parent);
	function_location->instrumentation_type = instrumentation_type;
end:
	return status;
}

int lttng_userspace_probe_location_tracepoint_get_binary_fd(
		const struct lttng_userspace_probe_location *location)
{
	int ret = -1;
	struct lttng_userspace_probe_location_tracepoint *tracepoint_location;

	if (!location || lttng_userspace_probe_location_get_type(location) !=
			LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT) {
		ERR("Invalid argument(s) passed to '%s'", __FUNCTION__);
		goto end;
	}

	tracepoint_location = container_of(location,
		struct lttng_userspace_probe_location_tracepoint, parent);
	ret = tracepoint_location->binary_fd_handle ?
			fd_handle_get_fd(tracepoint_location->binary_fd_handle) : -1;
end:
	return ret;
}

static struct lttng_userspace_probe_location_lookup_method *
lttng_userspace_probe_location_function_get_lookup_method(
		const struct lttng_userspace_probe_location *location)
{
	struct lttng_userspace_probe_location_lookup_method *ret = NULL;

	if (!location || lttng_userspace_probe_location_get_type(location) !=
			LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION) {
		ERR("Invalid argument(s) passed to '%s'", __FUNCTION__);
		goto end;
	}

	ret = location->lookup_method;
end:
	return ret;
}

static struct lttng_userspace_probe_location_lookup_method *
lttng_userspace_probe_location_tracepoint_get_lookup_method(
		const struct lttng_userspace_probe_location *location)
{
	struct lttng_userspace_probe_location_lookup_method *ret = NULL;

	if (!location || lttng_userspace_probe_location_get_type(location) !=
			LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT) {
		ERR("Invalid argument(s) passed to '%s'", __FUNCTION__);
		goto end;
	}

	ret = location->lookup_method;
end:
	return ret;
}

const struct lttng_userspace_probe_location_lookup_method *
lttng_userspace_probe_location_get_lookup_method(
		const struct lttng_userspace_probe_location *location)
{
	struct lttng_userspace_probe_location_lookup_method *ret = NULL;

	assert(location);
	switch (location->type) {
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION:
	ret = lttng_userspace_probe_location_function_get_lookup_method(
			location);
		break;
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT:
	ret = lttng_userspace_probe_location_tracepoint_get_lookup_method(
			location);
		break;
	default:
		ERR("Unknowned lookup method.");
		break;
	}
	return ret;
}

static
int lttng_userspace_probe_location_lookup_method_serialize(
		struct lttng_userspace_probe_location_lookup_method *method,
		struct lttng_payload *payload)
{
	int ret;
	struct lttng_userspace_probe_location_lookup_method_comm
			lookup_method_comm;

	lookup_method_comm.type = (int8_t) (method ? method->type :
			LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_DEFAULT);
	if (payload) {
		ret = lttng_dynamic_buffer_append(&payload->buffer, &lookup_method_comm,
				sizeof(lookup_method_comm));
		if (ret) {
			goto end;
		}
	}
	ret = sizeof(lookup_method_comm);
end:
	return ret;
}

static
int lttng_userspace_probe_location_function_serialize(
		const struct lttng_userspace_probe_location *location,
		struct lttng_payload *payload)
{
	int ret;
	size_t function_name_len, binary_path_len;
	struct lttng_userspace_probe_location_function *location_function;
	struct lttng_userspace_probe_location_function_comm location_function_comm;

	assert(location);
	assert(lttng_userspace_probe_location_get_type(location) ==
			LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION);

	location_function = container_of(location,
			struct lttng_userspace_probe_location_function,
			parent);
	if (!location_function->function_name || !location_function->binary_path) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (payload && !location_function->binary_fd_handle) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	function_name_len = strlen(location_function->function_name);
	if (function_name_len == 0) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}
	binary_path_len = strlen(location_function->binary_path);
	if (binary_path_len == 0) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	location_function_comm.function_name_len = function_name_len + 1;
	location_function_comm.binary_path_len = binary_path_len + 1;

	if (payload) {
		ret = lttng_dynamic_buffer_append(&payload->buffer,
				&location_function_comm,
				sizeof(location_function_comm));
		if (ret) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
		ret = lttng_dynamic_buffer_append(&payload->buffer,
				location_function->function_name,
				location_function_comm.function_name_len);
		if (ret) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
		ret = lttng_dynamic_buffer_append(&payload->buffer,
				location_function->binary_path,
				location_function_comm.binary_path_len);
		if (ret) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
		ret = lttng_payload_push_fd_handle(
				payload, location_function->binary_fd_handle);
		if (ret) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
	}
	ret = sizeof(location_function_comm) +
			location_function_comm.function_name_len +
			location_function_comm.binary_path_len;
end:
	return ret;
}

static
int lttng_userspace_probe_location_tracepoint_serialize(
		const struct lttng_userspace_probe_location *location,
		struct lttng_payload *payload)
{
	int ret;
	size_t probe_name_len, provider_name_len, binary_path_len;
	struct lttng_userspace_probe_location_tracepoint *location_tracepoint;
	struct lttng_userspace_probe_location_tracepoint_comm location_tracepoint_comm;

	assert(location);
	assert(lttng_userspace_probe_location_get_type(location) ==
			LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT);

	location_tracepoint = container_of(location,
			struct lttng_userspace_probe_location_tracepoint,
			parent);
	if (!location_tracepoint->probe_name ||
			!location_tracepoint->provider_name ||
			!location_tracepoint->binary_path) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (payload && !location_tracepoint->binary_fd_handle) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	probe_name_len = strlen(location_tracepoint->probe_name);
	if (probe_name_len == 0) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	provider_name_len = strlen(location_tracepoint->provider_name);
	if (provider_name_len == 0) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	binary_path_len = strlen(location_tracepoint->binary_path);
	if (binary_path_len == 0) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	location_tracepoint_comm.probe_name_len = probe_name_len + 1;
	location_tracepoint_comm.provider_name_len = provider_name_len + 1;
	location_tracepoint_comm.binary_path_len = binary_path_len + 1;

	if (payload) {
		ret = lttng_dynamic_buffer_append(&payload->buffer,
				&location_tracepoint_comm,
				sizeof(location_tracepoint_comm));
		if (ret) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
		ret = lttng_dynamic_buffer_append(&payload->buffer,
				location_tracepoint->probe_name,
				location_tracepoint_comm.probe_name_len);
		if (ret) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
		ret = lttng_dynamic_buffer_append(&payload->buffer,
				location_tracepoint->provider_name,
				location_tracepoint_comm.provider_name_len);
		if (ret) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
		ret = lttng_dynamic_buffer_append(&payload->buffer,
				location_tracepoint->binary_path,
				location_tracepoint_comm.binary_path_len);
		if (ret) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
		ret = lttng_payload_push_fd_handle(
				payload, location_tracepoint->binary_fd_handle);
		if (ret) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
	}

	ret = sizeof(location_tracepoint_comm) +
			location_tracepoint_comm.probe_name_len +
			location_tracepoint_comm.provider_name_len +
			location_tracepoint_comm.binary_path_len;
end:
	return ret;
}

LTTNG_HIDDEN
int lttng_userspace_probe_location_serialize(
		const struct lttng_userspace_probe_location *location,
		struct lttng_payload *payload)
{
	int ret, buffer_use = 0;
	struct lttng_userspace_probe_location_comm location_generic_comm;

	if (!location) {
		ERR("Invalid argument(s) passed to '%s'", __FUNCTION__);
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	memset(&location_generic_comm, 0, sizeof(location_generic_comm));

	location_generic_comm.type = (int8_t) location->type;
	if (payload) {
		ret = lttng_dynamic_buffer_append(&payload->buffer,
				&location_generic_comm,
				sizeof(location_generic_comm));
		if (ret) {
			goto end;
		}
	}
	buffer_use += sizeof(location_generic_comm);

	switch (lttng_userspace_probe_location_get_type(location)) {
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION:
		ret = lttng_userspace_probe_location_function_serialize(
				location, payload);
		break;
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT:
		ret = lttng_userspace_probe_location_tracepoint_serialize(
				location, payload);
		break;
	default:
		ERR("Unsupported probe location type");
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}
	if (ret < 0) {
		goto end;
	}
	buffer_use += ret;

	ret = lttng_userspace_probe_location_lookup_method_serialize(
			location->lookup_method, payload);
	if (ret < 0) {
		goto end;
	}
	ret += buffer_use;
end:
	return ret;
}

static
int lttng_userspace_probe_location_function_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_userspace_probe_location **location)
{
	struct lttng_userspace_probe_location_function_comm *location_function_comm;
	const char *function_name_src, *binary_path_src;
	char *function_name = NULL, *binary_path = NULL;
	int ret = 0;
	size_t expected_size;
	struct fd_handle *binary_fd_handle = lttng_payload_view_pop_fd_handle(view);

	assert(location);

	if (view->buffer.size < sizeof(*location_function_comm)) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	location_function_comm =
			(typeof(location_function_comm)) view->buffer.data;

	expected_size = sizeof(*location_function_comm) +
			location_function_comm->function_name_len +
			location_function_comm->binary_path_len;

	if (view->buffer.size < expected_size) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	function_name_src = view->buffer.data + sizeof(*location_function_comm);
	binary_path_src = function_name_src +
			location_function_comm->function_name_len;

	if (!lttng_buffer_view_contains_string(&view->buffer, function_name_src,
			    location_function_comm->function_name_len)) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (!lttng_buffer_view_contains_string(&view->buffer, binary_path_src,
			    location_function_comm->binary_path_len)) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	function_name = lttng_strndup(function_name_src, LTTNG_SYMBOL_NAME_LEN);
	if (!function_name) {
		PERROR("lttng_strndup");
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	binary_path = lttng_strndup(binary_path_src, LTTNG_PATH_MAX);
	if (!binary_path) {
		PERROR("lttng_strndup");
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	*location = lttng_userspace_probe_location_function_create_no_check(
			binary_path, function_name, NULL, false);
	if (!(*location)) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = lttng_userspace_probe_location_function_set_binary_fd_handle(
			*location, binary_fd_handle);
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = (int) expected_size;
end:
	fd_handle_put(binary_fd_handle);
	free(function_name);
	free(binary_path);
	return ret;
}

static
int lttng_userspace_probe_location_tracepoint_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_userspace_probe_location **location)
{
	struct lttng_userspace_probe_location_tracepoint_comm *location_tracepoint_comm;
	const char *probe_name_src, *provider_name_src, *binary_path_src;
	char *probe_name = NULL, *provider_name = NULL, *binary_path = NULL;
	int ret = 0;
	size_t expected_size;
	struct fd_handle *binary_fd_handle = lttng_payload_view_pop_fd_handle(view);

	assert(location);

	if (!binary_fd_handle) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (view->buffer.size < sizeof(*location_tracepoint_comm)) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	location_tracepoint_comm =
			(typeof(location_tracepoint_comm)) view->buffer.data;

	expected_size = sizeof(*location_tracepoint_comm) +
			location_tracepoint_comm->probe_name_len +
			location_tracepoint_comm->provider_name_len +
			location_tracepoint_comm->binary_path_len;

	if (view->buffer.size < expected_size) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	probe_name_src = view->buffer.data + sizeof(*location_tracepoint_comm);
	provider_name_src = probe_name_src +
			location_tracepoint_comm->probe_name_len;
	binary_path_src = provider_name_src +
			location_tracepoint_comm->provider_name_len;

	if (!lttng_buffer_view_contains_string(&view->buffer, probe_name_src,
			    location_tracepoint_comm->probe_name_len)) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (!lttng_buffer_view_contains_string(&view->buffer, provider_name_src,
			    location_tracepoint_comm->provider_name_len)) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (!lttng_buffer_view_contains_string(&view->buffer, binary_path_src,
			    location_tracepoint_comm->binary_path_len)) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	probe_name = lttng_strndup(probe_name_src, LTTNG_SYMBOL_NAME_LEN);
	if (!probe_name) {
		PERROR("lttng_strndup");
		goto end;
	}
	provider_name = lttng_strndup(provider_name_src, LTTNG_SYMBOL_NAME_LEN);
	if (!provider_name) {
		PERROR("lttng_strndup");
		goto end;
	}

	binary_path = lttng_strndup(binary_path_src, LTTNG_SYMBOL_NAME_LEN);
	if (!binary_path) {
		PERROR("lttng_strndup");
		goto end;
	}

	*location = lttng_userspace_probe_location_tracepoint_create_no_check(
			binary_path, provider_name, probe_name, NULL, false);
	if (!(*location)) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = lttng_userspace_probe_location_tracepoint_set_binary_fd_handle(
			*location, binary_fd_handle);
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = (int) expected_size;
end:
	fd_handle_put(binary_fd_handle);
	free(probe_name);
	free(provider_name);
	free(binary_path);
	return ret;
}

static
int lttng_userspace_probe_location_lookup_method_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_userspace_probe_location_lookup_method **lookup_method)
{
	int ret;
	struct lttng_userspace_probe_location_lookup_method_comm *lookup_comm;
	enum lttng_userspace_probe_location_lookup_method_type type;

	assert(view);
	assert(lookup_method);

	if (view->buffer.size < sizeof(*lookup_comm)) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	lookup_comm = (typeof(lookup_comm)) view->buffer.data;
	type = (enum lttng_userspace_probe_location_lookup_method_type)
			lookup_comm->type;
	switch (type) {
	case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_DEFAULT:
		*lookup_method = NULL;
		break;
	case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF:
		*lookup_method =
			lttng_userspace_probe_location_lookup_method_function_elf_create();
		if (!(*lookup_method)) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
		break;
	case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT:
		*lookup_method =
			lttng_userspace_probe_location_lookup_method_tracepoint_sdt_create();
		if (!(*lookup_method)) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
		break;
	default:
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = sizeof(*lookup_comm);
end:
	return ret;
}

LTTNG_HIDDEN
int lttng_userspace_probe_location_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_userspace_probe_location **location)
{
	struct lttng_userspace_probe_location_lookup_method *lookup_method;
	struct lttng_userspace_probe_location_comm *probe_location_comm;
	enum lttng_userspace_probe_location_type type;
	int consumed = 0;
	int ret;

	assert(view);
	assert(location);

	lookup_method = NULL;

	if (view->buffer.size <= sizeof(*probe_location_comm)) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	probe_location_comm = (typeof(probe_location_comm)) view->buffer.data;
	type = (enum lttng_userspace_probe_location_type) probe_location_comm->type;
	consumed += sizeof(*probe_location_comm);

	switch (type) {
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION:
	{
		struct lttng_payload_view location_view =
				lttng_payload_view_from_view(
						view, consumed, -1);

		ret = lttng_userspace_probe_location_function_create_from_payload(
				&location_view, location);
		if (ret < 0) {
			goto end;
		}
		break;
	}
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT:
	{
		struct lttng_payload_view location_view =
				lttng_payload_view_from_view(view, consumed, -1);

		ret = lttng_userspace_probe_location_tracepoint_create_from_payload(
				&location_view, location);
		if (ret < 0) {
			goto end;
		}
		break;
	}
	default:
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	consumed += ret;
	if (view->buffer.size <= consumed) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	{
		struct lttng_payload_view lookup_method_view =
				lttng_payload_view_from_view(
						view, consumed, -1);

		ret = lttng_userspace_probe_location_lookup_method_create_from_payload(
				&lookup_method_view, &lookup_method);
	}
	if (ret < 0) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	assert(lookup_method);
	(*location)->lookup_method = lookup_method;
	lookup_method = NULL;
	ret += consumed;
end:
	return ret;
}

static
int lttng_userspace_probe_location_function_set_binary_fd_handle(
		struct lttng_userspace_probe_location *location,
		struct fd_handle *binary_fd)	
{
	int ret = 0;
	struct lttng_userspace_probe_location_function *function_location;

	assert(location);
	assert(location->type == LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION);

	function_location = container_of(location,
			struct lttng_userspace_probe_location_function, parent);
	fd_handle_put(function_location->binary_fd_handle);
	fd_handle_get(binary_fd);
	function_location->binary_fd_handle = binary_fd;
	return ret;
}

static
int lttng_userspace_probe_location_tracepoint_set_binary_fd_handle(
		struct lttng_userspace_probe_location *location,
		struct fd_handle *binary_fd)
{
	int ret = 0;
	struct lttng_userspace_probe_location_tracepoint *tracepoint_location;

	assert(location);
	assert(location->type == LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT);

	tracepoint_location = container_of(location,
			struct lttng_userspace_probe_location_tracepoint, parent);
	fd_handle_put(tracepoint_location->binary_fd_handle);
	fd_handle_get(binary_fd);
	tracepoint_location->binary_fd_handle = binary_fd;
	return ret;
}

static
int lttng_userspace_probe_location_function_flatten(
		const struct lttng_userspace_probe_location *location,
		struct lttng_dynamic_buffer *buffer)
{
	struct lttng_userspace_probe_location_lookup_method_elf flat_lookup_method;
	struct lttng_userspace_probe_location_function *probe_function;
	struct lttng_userspace_probe_location_function flat_probe;
	size_t function_name_len, binary_path_len;
	size_t padding_needed = 0;
	char *flat_probe_start;
	int storage_needed = 0;
	int ret;

	assert(location);

	if (location->lookup_method && location->lookup_method->type !=
			LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	probe_function = container_of(location,
			struct lttng_userspace_probe_location_function,
			parent);
	assert(probe_function->function_name);
	assert(probe_function->binary_path);

	storage_needed +=
			sizeof(struct lttng_userspace_probe_location_function);
	function_name_len = strlen(probe_function->function_name) + 1;
	binary_path_len = strlen(probe_function->binary_path) + 1;
	storage_needed += function_name_len + binary_path_len;

	/*
	 * The lookup method is aligned to 64-bit within the buffer.
	 * This is needed even if there is no lookup method since
	 * the next structure in the buffer probably needs to be
	 * aligned too (depending on the arch).
	 */
	padding_needed = ALIGN_TO(storage_needed, sizeof(uint64_t)) - storage_needed;
	storage_needed += padding_needed;

	if (location->lookup_method) {
		/* NOTE: elf look-up method is assumed here. */
		storage_needed += sizeof(struct lttng_userspace_probe_location_lookup_method_elf);
	}

	if (!buffer) {
		ret = storage_needed;
		goto end;
	}

	if (lttng_dynamic_buffer_get_capacity_left(buffer) < storage_needed) {
		ret = lttng_dynamic_buffer_set_capacity(buffer,
				buffer->size + storage_needed);
		if (ret) {
			goto end;
		}
	}

	memset(&flat_probe, 0, sizeof(flat_probe));

	flat_probe_start = buffer->data + buffer->size;
	flat_probe.parent.type = location->type;
	/*
	 * The lookup method, if present, is the last element in the flat
	 * representation of the probe.
	 */
	if (location->lookup_method) {
		flat_probe.parent.lookup_method =
				(struct lttng_userspace_probe_location_lookup_method *)
					(flat_probe_start + sizeof(flat_probe) +
					function_name_len + binary_path_len + padding_needed);
	} else {
		flat_probe.parent.lookup_method = NULL;
	}

	flat_probe.function_name = flat_probe_start + sizeof(flat_probe);
	flat_probe.binary_path = flat_probe.function_name + function_name_len;
	flat_probe.binary_fd_handle = NULL;
	ret = lttng_dynamic_buffer_append(buffer, &flat_probe,
			sizeof(flat_probe));
	if (ret) {
		goto end;
	}

	ret = lttng_dynamic_buffer_append(buffer,
			probe_function->function_name, function_name_len);
	if (ret) {
		goto end;
	}
	ret = lttng_dynamic_buffer_append(buffer,
			probe_function->binary_path, binary_path_len);
	if (ret) {
		goto end;
	}

	/* Insert padding before the lookup method. */
	ret = lttng_dynamic_buffer_set_size(buffer,
			buffer->size + padding_needed);
	if (ret) {
		goto end;
	}

	if (!location->lookup_method) {
		/* Not an error, the default method is used. */
		ret = storage_needed;
		goto end;
	}

	memset(&flat_lookup_method, 0, sizeof(flat_lookup_method));
	flat_lookup_method.parent.type =
			LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF;
	ret = lttng_dynamic_buffer_append(buffer,
			&flat_lookup_method, sizeof(flat_lookup_method));
	if (ret) {
		goto end;
	}
	ret = storage_needed;
end:
	return ret;
}

static
int lttng_userspace_probe_location_tracepoint_flatten(
		const struct lttng_userspace_probe_location *location,
		struct lttng_dynamic_buffer *buffer)
{
	struct lttng_userspace_probe_location_lookup_method_sdt flat_lookup_method;
	struct lttng_userspace_probe_location_tracepoint *probe_tracepoint;
	struct lttng_userspace_probe_location_tracepoint flat_probe;
	size_t probe_name_len, provider_name_len, binary_path_len;
	size_t padding_needed = 0;
	int storage_needed = 0;
	char *flat_probe_start;
	int ret = 0;

	assert(location);

	/* Only SDT tracepoints are supported at the moment */
	if (location->lookup_method && location->lookup_method->type !=
			LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}
	probe_tracepoint = container_of(location,
			struct lttng_userspace_probe_location_tracepoint,
			parent);
	assert(probe_tracepoint->probe_name);
	assert(probe_tracepoint->provider_name);
	assert(probe_tracepoint->binary_path);

	/* Compute the storage space needed to flatten the probe location */
	storage_needed += sizeof(struct lttng_userspace_probe_location_tracepoint);

	probe_name_len = strlen(probe_tracepoint->probe_name) + 1;
	provider_name_len = strlen(probe_tracepoint->provider_name) + 1;
	binary_path_len = strlen(probe_tracepoint->binary_path) + 1;

	storage_needed += probe_name_len + provider_name_len + binary_path_len;

	/*
	 * The lookup method is aligned to 64-bit within the buffer.
	 * This is needed even if there is no lookup method since
	 * the next structure in the buffer probably needs to be
	 * aligned too (depending on the arch).
	 */
	padding_needed = ALIGN_TO(storage_needed, sizeof(uint64_t)) - storage_needed;
	storage_needed += padding_needed;

	if (location->lookup_method) {
		/* NOTE: elf look-up method is assumed here. */
		storage_needed +=
			sizeof(struct lttng_userspace_probe_location_lookup_method_elf);
	}

	/*
	 * If the caller set buffer to NULL, return the size of the needed buffer.
	 */
	if (!buffer) {
		ret = storage_needed;
		goto end;
	}

	if (lttng_dynamic_buffer_get_capacity_left(buffer) < storage_needed) {
		ret = lttng_dynamic_buffer_set_capacity(buffer,
				buffer->size + storage_needed);
		if (ret) {
			goto end;
		}
	}

	memset(&flat_probe, 0, sizeof(flat_probe));

	flat_probe_start = buffer->data + buffer->size;
	flat_probe.parent.type = location->type;

	/*
	 * The lookup method, if present, is the last element in the flat
	 * representation of the probe.
	 */
	if (location->lookup_method) {
		flat_probe.parent.lookup_method =
				(struct lttng_userspace_probe_location_lookup_method *)
					(flat_probe_start + sizeof(flat_probe) +
					probe_name_len + provider_name_len +
					binary_path_len + padding_needed);
	} else {
		flat_probe.parent.lookup_method = NULL;
	}

	flat_probe.probe_name = flat_probe_start + sizeof(flat_probe);
	flat_probe.provider_name = flat_probe.probe_name + probe_name_len;
	flat_probe.binary_path = flat_probe.provider_name + provider_name_len;
	flat_probe.binary_fd_handle = NULL;
	ret = lttng_dynamic_buffer_append(buffer, &flat_probe, sizeof(flat_probe));
	if (ret) {
		goto end;
	}

	/* Append all the fields to the buffer */
	ret = lttng_dynamic_buffer_append(buffer,
			probe_tracepoint->probe_name, probe_name_len);
	if (ret) {
		goto end;
	}
	ret = lttng_dynamic_buffer_append(buffer,
			probe_tracepoint->provider_name, provider_name_len);
	if (ret) {
		goto end;
	}
	ret = lttng_dynamic_buffer_append(buffer,
			probe_tracepoint->binary_path, binary_path_len);
	if (ret) {
		goto end;
	}

	/* Insert padding before the lookup method. */
	ret = lttng_dynamic_buffer_set_size(buffer, buffer->size + padding_needed);
	if (ret) {
		goto end;
	}

	if (!location->lookup_method) {
		/* Not an error, the default method is used. */
		ret = storage_needed;
		goto end;
	}

	memset(&flat_lookup_method, 0, sizeof(flat_lookup_method));

	flat_lookup_method.parent.type =
			LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT;
	ret = lttng_dynamic_buffer_append(buffer,
			&flat_lookup_method, sizeof(flat_lookup_method));
	if (ret) {
		goto end;
	}
	ret = storage_needed;
end:
	return ret;
}

LTTNG_HIDDEN
int lttng_userspace_probe_location_flatten(
		const struct lttng_userspace_probe_location *location,
		struct lttng_dynamic_buffer *buffer)
{
	int ret;
	if (!location) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	/* Only types currently supported. */
	switch (location->type) {
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION:
		ret = lttng_userspace_probe_location_function_flatten(location, buffer);
		break;
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT:
		ret = lttng_userspace_probe_location_tracepoint_flatten(location, buffer);
		break;
	default:
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

end:
	return ret;
}

LTTNG_HIDDEN
struct lttng_userspace_probe_location *lttng_userspace_probe_location_copy(
		const struct lttng_userspace_probe_location *location)
{
	struct lttng_userspace_probe_location *new_location = NULL;
	enum lttng_userspace_probe_location_type type;

	if (!location) {
		goto err;
	}

	type = lttng_userspace_probe_location_get_type(location);
	switch (type) {
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION:
		new_location =
			lttng_userspace_probe_location_function_copy(location);
		if (!new_location) {
			goto err;
		}
		break;
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT:
		new_location =
			lttng_userspace_probe_location_tracepoint_copy(location);
		if (!new_location) {
			goto err;
		}
		break;
	default:
		new_location = NULL;
		goto err;
	}
err:
	return new_location;
}

LTTNG_HIDDEN
bool lttng_userspace_probe_location_lookup_method_is_equal(
		const struct lttng_userspace_probe_location_lookup_method *a,
		const struct lttng_userspace_probe_location_lookup_method *b)
{
	bool is_equal = false;

	if (!a || !b) {
		goto end;
	}

	if (a == b) {
		is_equal = true;
		goto end;
	}

	if (a->type != b->type) {
		goto end;
	}

	is_equal = true;
end:
	return is_equal;
}

LTTNG_HIDDEN
bool lttng_userspace_probe_location_is_equal(
		const struct lttng_userspace_probe_location *a,
		const struct lttng_userspace_probe_location *b)
{
	bool is_equal = false;

	if (!a || !b) {
		goto end;
	}

	if (a == b) {
		is_equal = true;
		goto end;
	}

	if (!lttng_userspace_probe_location_lookup_method_is_equal(
			    a->lookup_method, b->lookup_method)) {
		goto end;
	}

	if (a->type != b->type) {
		goto end;
	}

	is_equal = a->equal ? a->equal(a, b) : true;
end:
	return is_equal;
}
