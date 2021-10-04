/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <assert.h>
#include <common/error.h>
#include <common/macros.h>
#include <common/compat/string.h>
#include <fcntl.h>
#include <lttng/constant.h>
#include <lttng/userspace-probe-internal.h>

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
	if (location_function->binary_fd >= 0) {
		if (close(location_function->binary_fd)) {
			PERROR("close");
		}
	}
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
	if (location_tracepoint->binary_fd >= 0) {
		if (close(location_tracepoint->binary_fd)) {
			PERROR("close");
		}
	}
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

static struct lttng_userspace_probe_location *
lttng_userspace_probe_location_function_create_no_check(const char *binary_path,
		const char *function_name,
		struct lttng_userspace_probe_location_lookup_method *lookup_method,
		bool open_binary)
{
	int binary_fd = -1;
	char *function_name_copy = NULL, *binary_path_copy = NULL;
	struct lttng_userspace_probe_location *ret = NULL;
	struct lttng_userspace_probe_location_function *location;

	if (open_binary) {
		binary_fd = open(binary_path, O_RDONLY);
		if (binary_fd < 0) {
			PERROR("Error opening the binary");
			goto error;
		}
	} else {
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
	location->binary_fd = binary_fd;
	location->instrumentation_type =
			LTTNG_USERSPACE_PROBE_LOCATION_FUNCTION_INSTRUMENTATION_TYPE_ENTRY;

	ret = &location->parent;
	ret->lookup_method = lookup_method;
	ret->type = LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION;
	goto end;

error:
	free(function_name_copy);
	free(binary_path_copy);
	if (binary_fd >= 0) {
		if (close(binary_fd)) {
			PERROR("Error closing binary fd in error path");
		}
	}
end:
	return ret;
}

static struct lttng_userspace_probe_location *
lttng_userspace_probe_location_tracepoint_create_no_check(const char *binary_path,
		const char *provider_name, const char *probe_name,
		struct lttng_userspace_probe_location_lookup_method *lookup_method,
		bool open_binary)
{
	int binary_fd = -1;
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
	} else {
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
	location->binary_fd = binary_fd;

	ret = &location->parent;
	ret->lookup_method = lookup_method;
	ret->type = LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT;
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
		ERR("Invalid argument(s)");
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
		ERR("Invalid argument(s)");
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
	int fd, new_fd;

	assert(location);
	assert(location->type == LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION);

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

	/* Duplicate the binary fd */
	fd = lttng_userspace_probe_location_function_get_binary_fd(location);
	if (fd == -1) {
		ERR("Error getting file descriptor to binary");
		goto error;
	}

	new_fd = dup(fd);
	if (new_fd == -1) {
		PERROR("Error duplicating file descriptor to binary");
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
			goto close_fd;
		}
		break;
	default:
		/* Invalid probe location lookup method. */
		goto close_fd;
	}

	/* Create the probe_location */
	new_location = lttng_userspace_probe_location_function_create_no_check(
			binary_path, function_name, lookup_method, false);
	if (!new_location) {
		goto destroy_lookup_method;
	}

	/* Set the duplicated fd to the new probe_location */
	if (lttng_userspace_probe_location_function_set_binary_fd(new_location, new_fd) < 0) {
		goto destroy_probe_location;
	}

	goto end;

destroy_probe_location:
	lttng_userspace_probe_location_destroy(new_location);
destroy_lookup_method:
	lttng_userspace_probe_location_lookup_method_destroy(lookup_method);
close_fd:
	if (close(new_fd) < 0) {
		PERROR("Error closing duplicated file descriptor in error path");
	}
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
	int fd, new_fd;

	assert(location);
	assert(location->type == LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT);

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

	/* Duplicate the binary fd */
	fd = lttng_userspace_probe_location_tracepoint_get_binary_fd(location);
	if (fd == -1) {
		ERR("Error getting file descriptor to binary");
		goto error;
	}

	new_fd = dup(fd);
	if (new_fd == -1) {
		PERROR("Error duplicating file descriptor to binary");
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
			goto close_fd;
		}
		break;
	default:
		/* Invalid probe location lookup method. */
		goto close_fd;
	}

	/* Create the probe_location */
	new_location = lttng_userspace_probe_location_tracepoint_create_no_check(
			binary_path, provider_name, probe_name, lookup_method, false);
	if (!new_location) {
		goto destroy_lookup_method;
	}

	/* Set the duplicated fd to the new probe_location */
	if (lttng_userspace_probe_location_tracepoint_set_binary_fd(new_location, new_fd) < 0) {
		goto destroy_probe_location;
	}

	goto end;

destroy_probe_location:
	lttng_userspace_probe_location_destroy(new_location);
destroy_lookup_method:
	lttng_userspace_probe_location_lookup_method_destroy(lookup_method);
close_fd:
	if (close(new_fd) < 0) {
		PERROR("Error closing duplicated file descriptor in error path");
	}
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
		ERR("Invalid argument(s)");
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
		ERR("Invalid argument(s)");
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
		ERR("Invalid argument(s)");
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
		ERR("Invalid argument(s)");
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
		ERR("Invalid argument(s)");
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
		ERR("Invalid argument(s)");
		goto end;
	}

	function_location = container_of(location,
		struct lttng_userspace_probe_location_function, parent);
	ret = function_location->binary_fd;
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
		ERR("Invalid argument(s)");
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
		ERR("Invalid argument(s)");
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
		ERR("Invalid argument(s)");
		goto end;
	}

	tracepoint_location = container_of(location,
		struct lttng_userspace_probe_location_tracepoint, parent);
	ret = tracepoint_location->binary_fd;
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
		ERR("Invalid argument(s)");
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
		ERR("Invalid argument(s)");
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
		struct lttng_dynamic_buffer *buffer)
{
	int ret;
	struct lttng_userspace_probe_location_lookup_method_comm
			lookup_method_comm;

	lookup_method_comm.type = (int8_t) (method ? method->type :
			LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_DEFAULT);
	if (buffer) {
		ret = lttng_dynamic_buffer_append(buffer, &lookup_method_comm,
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
		struct lttng_dynamic_buffer *buffer,
		int *binary_fd)
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

	if (binary_fd && location_function->binary_fd < 0) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (binary_fd) {
		*binary_fd = location_function->binary_fd;
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

	if (buffer) {
		ret = lttng_dynamic_buffer_append(buffer,
				&location_function_comm,
				sizeof(location_function_comm));
		if (ret) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
		ret = lttng_dynamic_buffer_append(buffer,
				location_function->function_name,
				location_function_comm.function_name_len);
		if (ret) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
		ret = lttng_dynamic_buffer_append(buffer,
				location_function->binary_path,
				location_function_comm.binary_path_len);
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
		struct lttng_dynamic_buffer *buffer,
		int *binary_fd)
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

	if (binary_fd && location_tracepoint->binary_fd < 0) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (binary_fd) {
		*binary_fd = location_tracepoint->binary_fd;
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

	if (buffer) {
		ret = lttng_dynamic_buffer_append(buffer,
				&location_tracepoint_comm,
				sizeof(location_tracepoint_comm));
		if (ret) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
		ret = lttng_dynamic_buffer_append(buffer,
				location_tracepoint->probe_name,
				location_tracepoint_comm.probe_name_len);
		if (ret) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
		ret = lttng_dynamic_buffer_append(buffer,
				location_tracepoint->provider_name,
				location_tracepoint_comm.provider_name_len);
		if (ret) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
		ret = lttng_dynamic_buffer_append(buffer,
				location_tracepoint->binary_path,
				location_tracepoint_comm.binary_path_len);
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
		struct lttng_dynamic_buffer *buffer,
		int *binary_fd)
{
	int ret, buffer_use = 0;
	struct lttng_userspace_probe_location_comm location_generic_comm;

	if (!location) {
		ERR("Invalid argument(s)");
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	memset(&location_generic_comm, 0, sizeof(location_generic_comm));

	location_generic_comm.type = (int8_t) location->type;
	if (buffer) {
		ret = lttng_dynamic_buffer_append(buffer, &location_generic_comm,
				sizeof(location_generic_comm));
		if (ret) {
			goto end;
		}
	}
	buffer_use += sizeof(location_generic_comm);

	switch (lttng_userspace_probe_location_get_type(location)) {
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION:
		ret = lttng_userspace_probe_location_function_serialize(
				location, buffer, binary_fd);
		break;
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT:
		ret = lttng_userspace_probe_location_tracepoint_serialize(
				location, buffer, binary_fd);
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
			location->lookup_method, buffer);
	if (ret < 0) {
		goto end;
	}
	ret += buffer_use;
end:
	return ret;
}

static
int lttng_userspace_probe_location_function_create_from_buffer(
		const struct lttng_buffer_view *buffer,
		struct lttng_userspace_probe_location **location)
{
	struct lttng_userspace_probe_location_function_comm *location_function_comm;
	const char *function_name_src, *binary_path_src;
	char *function_name = NULL, *binary_path = NULL;
	int ret = 0;

	assert(buffer);
	assert(buffer->data);
	assert(location);

	location_function_comm =
		(struct lttng_userspace_probe_location_function_comm *) buffer->data;

	const size_t expected_size = sizeof(*location_function_comm) +
			location_function_comm->function_name_len +
			location_function_comm->binary_path_len;

	if (buffer->size < expected_size) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	function_name_src = buffer->data + sizeof(*location_function_comm);
	binary_path_src = function_name_src +
			location_function_comm->function_name_len;

	if (function_name_src[location_function_comm->function_name_len - 1] != '\0') {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}
	if (binary_path_src[location_function_comm->binary_path_len - 1] != '\0') {
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

	ret = (int) expected_size;
end:
	free(function_name);
	free(binary_path);
	return ret;
}

static
int lttng_userspace_probe_location_tracepoint_create_from_buffer(
		const struct lttng_buffer_view *buffer,
		struct lttng_userspace_probe_location **location)
{
	struct lttng_userspace_probe_location_tracepoint_comm *location_tracepoint_comm;
	const char *probe_name_src, *provider_name_src, *binary_path_src;
	char *probe_name = NULL, *provider_name = NULL, *binary_path = NULL;
	int ret = 0;

	assert(buffer);
	assert(buffer->data);
	assert(location);

	location_tracepoint_comm =
		(struct lttng_userspace_probe_location_tracepoint_comm *) buffer->data;

	const size_t expected_size = sizeof(*location_tracepoint_comm) +
			location_tracepoint_comm->probe_name_len +
			location_tracepoint_comm->provider_name_len +
			location_tracepoint_comm->binary_path_len;

	if (buffer->size < expected_size) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	probe_name_src = buffer->data + sizeof(*location_tracepoint_comm);
	provider_name_src = probe_name_src +
			location_tracepoint_comm->probe_name_len;
	binary_path_src = provider_name_src +
			location_tracepoint_comm->provider_name_len;

	if (probe_name_src[location_tracepoint_comm->probe_name_len - 1] != '\0') {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (provider_name_src[location_tracepoint_comm->provider_name_len - 1] != '\0') {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (binary_path_src[location_tracepoint_comm->binary_path_len - 1] != '\0') {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	probe_name = lttng_strndup(probe_name_src, LTTNG_SYMBOL_NAME_LEN);
	if (!probe_name) {
		PERROR("Failed to allocate probe name");
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}
	provider_name = lttng_strndup(provider_name_src, LTTNG_SYMBOL_NAME_LEN);
	if (!provider_name) {
		PERROR("Failed to allocate provider name");
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	binary_path = lttng_strndup(binary_path_src, LTTNG_PATH_MAX);
	if (!binary_path) {
		PERROR("Failed to allocate binary path");
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	*location = lttng_userspace_probe_location_tracepoint_create_no_check(
			binary_path, provider_name, probe_name, NULL, false);
	if (!(*location)) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = (int) expected_size;
end:
	free(probe_name);
	free(provider_name);
	free(binary_path);
	return ret;
}

static
int lttng_userspace_probe_location_lookup_method_create_from_buffer(
		struct lttng_buffer_view *buffer,
		struct lttng_userspace_probe_location_lookup_method **lookup_method)
{
	int ret;
	struct lttng_userspace_probe_location_lookup_method_comm *lookup_comm;
	enum lttng_userspace_probe_location_lookup_method_type type;

	assert(buffer);
	assert(buffer->data);
	assert(lookup_method);

	if (buffer->size < sizeof(*lookup_comm)) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	lookup_comm = (struct lttng_userspace_probe_location_lookup_method_comm *)
			buffer->data;
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
int lttng_userspace_probe_location_create_from_buffer(
		const struct lttng_buffer_view *buffer,
		struct lttng_userspace_probe_location **location)
{
	struct lttng_userspace_probe_location_lookup_method *lookup_method;
	struct lttng_userspace_probe_location_comm *probe_location_comm;
	enum lttng_userspace_probe_location_type type;
	struct lttng_buffer_view lookup_method_view;
	int consumed = 0;
	int ret;


	assert(buffer);
	assert(buffer->data);
	assert(location);

	lookup_method = NULL;

	if (buffer->size <= sizeof(*probe_location_comm)) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	probe_location_comm =
		(struct lttng_userspace_probe_location_comm *) buffer->data;
	type = (enum lttng_userspace_probe_location_type) probe_location_comm->type;
	consumed += sizeof(*probe_location_comm);

	switch (type) {
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION:
	{
		struct lttng_buffer_view view = lttng_buffer_view_from_view(
			buffer, consumed, buffer->size - consumed);

		ret = lttng_userspace_probe_location_function_create_from_buffer(
				&view, location);
		if (ret < 0) {
			goto end;
		}
		break;
	}
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT:
	{
		struct lttng_buffer_view view = lttng_buffer_view_from_view(
			buffer, consumed, buffer->size - consumed);

		ret = lttng_userspace_probe_location_tracepoint_create_from_buffer(
				&view, location);
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
	if (buffer->size <= consumed) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	lookup_method_view = lttng_buffer_view_from_view(buffer, consumed,
			buffer->size - consumed);
	ret = lttng_userspace_probe_location_lookup_method_create_from_buffer(
			&lookup_method_view, &lookup_method);
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

LTTNG_HIDDEN
int lttng_userspace_probe_location_function_set_binary_fd(
		struct lttng_userspace_probe_location *location, int binary_fd)
{
	int ret = 0;
	struct lttng_userspace_probe_location_function *function_location;

	assert(location);
	assert(location->type == LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION);

	function_location = container_of(location,
			struct lttng_userspace_probe_location_function, parent);
	if (function_location->binary_fd >= 0) {
		ret = close(function_location->binary_fd);
		if (ret) {
			PERROR("close");
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
	}

	function_location->binary_fd = binary_fd;
end:
	return ret;
}

LTTNG_HIDDEN
int lttng_userspace_probe_location_tracepoint_set_binary_fd(
		struct lttng_userspace_probe_location *location, int binary_fd)
{
	int ret = 0;
	struct lttng_userspace_probe_location_tracepoint *tracepoint_location;

	assert(location);
	assert(location->type == LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT);

	tracepoint_location = container_of(location,
			struct lttng_userspace_probe_location_tracepoint, parent);
	if (tracepoint_location->binary_fd >= 0) {
		ret = close(tracepoint_location->binary_fd);
		if (ret) {
			PERROR("close");
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
	}

	tracepoint_location->binary_fd = binary_fd;
end:
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
	flat_probe.binary_fd = -1;
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
	flat_probe.binary_fd = -1;
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
