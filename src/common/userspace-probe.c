/*
 * Copyright (C) 2017 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <lttng/userspace-probe-internal.h>
#include <common/macros.h>
#include <common/error.h>
#include <assert.h>
#include <fcntl.h>

enum lttng_userspace_probe_location_lookup_method_type
lttng_userspace_probe_location_lookup_method_get_type(
		struct lttng_userspace_probe_location_lookup_method *lookup_method)
{
	return lookup_method ? lookup_method->type :
		LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_UNKNOWN;
}

void lttng_userspace_probe_location_lookup_method_destroy(
		struct lttng_userspace_probe_location_lookup_method *lookup_method)
{
	switch (lookup_method->type) {
	case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF:
	{
		struct lttng_userspace_probe_location_lookup_method_elf *elf_method =
			container_of(lookup_method,
				 struct lttng_userspace_probe_location_lookup_method_elf, parent);
		free(elf_method);
		break;
	}
	default:
		break;
	}
}

struct lttng_userspace_probe_location_lookup_method *
lttng_userspace_probe_location_lookup_method_function_name_elf_create(void)
{
	struct lttng_userspace_probe_location_lookup_method *ret = NULL;
	struct lttng_userspace_probe_location_lookup_method_elf *elf_method;

	elf_method = zmalloc(sizeof(*elf_method));
	if (!elf_method) {
		goto end;
	}

	ret = &elf_method->parent;
	ret->type = LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF;
end:
	return ret;
}

enum lttng_userspace_probe_location_type lttng_userspace_probe_location_get_type(
		struct lttng_userspace_probe_location *location)
{
	return location ? location->type :
		LTTNG_USERSPACE_PROBE_LOCATION_TYPE_UNKNOWN;
}

static
void lttng_userspace_probe_location_function_destroy(
		struct lttng_userspace_probe_location *location)
{
	struct lttng_userspace_probe_location_function *location_function =
		container_of(location,
			struct lttng_userspace_probe_location_function,
			parent);

	free(location_function->function_name);
	free(location_function->binary_path);
	if (location_function->binary_fd >= 0) {
		if (close(location_function->binary_fd)) {
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
	default:
		free(location);
	}
}

static struct lttng_userspace_probe_location *
lttng_userspace_probe_location_function_create_no_check(const char *binary_path,
		const char *function_name,
		struct lttng_userspace_probe_location_lookup_method *lookup_method,
		bool open_binary)
{
	int binary_fd = -1;
	char *full_binary_path = NULL;
	char *function_name_copy = NULL;
	struct lttng_userspace_probe_location *ret = NULL;
	struct lttng_userspace_probe_location_function *location;

	full_binary_path = realpath(binary_path, NULL);
	if (!full_binary_path) {
		goto error;
	}

	if (open_binary) {
		binary_fd = open(full_binary_path, O_RDONLY);
		if (binary_fd < 0) {
			goto error;
		}
	} else {
		binary_fd = -1;
	}

	function_name_copy = strdup(function_name);
	if (!function_name_copy) {
		goto error;
	}

	location = zmalloc(sizeof(*location));
	if (!location) {
		goto error;
	}

	location->function_name = function_name_copy;
	location->binary_path = full_binary_path;
	location->binary_fd = binary_fd;

	ret = &location->parent;
	ret->lookup_method = lookup_method;
	ret->type = LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION;
end:
	return ret;
error:
	free(full_binary_path);
	free(function_name_copy);
	if (binary_fd >= 0) {
		if (close(binary_fd)) {
			PERROR("close");
		}
	}
	goto end;
}

struct lttng_userspace_probe_location *
lttng_userspace_probe_location_function_create(const char *binary_path,
		const char *function_name,
		struct lttng_userspace_probe_location_lookup_method *lookup_method)
{
	struct lttng_userspace_probe_location *ret = NULL;

	if (!binary_path || !function_name) {
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

static struct lttng_userspace_probe_location_lookup_method *
lttng_userspace_probe_location_lookup_method_function_name_elf_copy(
			struct lttng_userspace_probe_location_lookup_method *lookup_method)
{
	int ret;
	struct lttng_userspace_probe_location_lookup_method *parent = NULL;
	struct lttng_userspace_probe_location_lookup_method_elf *elf_method;
	assert(lookup_method->type ==
		   LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF);

	elf_method = zmalloc(sizeof(*elf_method));
	if (!elf_method) {
		goto error;
	}
	ret = lttng_userspace_probe_location_lookup_method_elf_get_run_as_ids(
				lookup_method, &elf_method->run_as_uid, &elf_method->run_as_gid);
	if (ret) {
		goto free_lookup_method;
	}

	elf_method->parent.type = lookup_method->type;
	parent = &elf_method->parent;

end:
	return parent;

free_lookup_method:
	free(elf_method);
error:
	parent = NULL;
	goto end;
}

static struct lttng_userspace_probe_location *
lttng_userspace_probe_location_function_copy(struct lttng_userspace_probe_location *location)
{
	enum lttng_userspace_probe_location_lookup_method_type lookup_type;
	struct lttng_userspace_probe_location *new_location = NULL;
	struct lttng_userspace_probe_location_lookup_method *lookup_method = NULL;
	char *binary_path = NULL;
	char *function_name = NULL;
	int fd;

	assert(location->type == LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION);

	 /* Duplicate probe location fields */
	binary_path =
		strdup(lttng_userspace_probe_location_function_get_binary_path(location));
	if (!binary_path) {
		goto error;
	}

	function_name =
		strdup(lttng_userspace_probe_location_function_get_function_name(location));
	if (!function_name) {
		goto free_binary_path;
	}

	/* Duplicate the binary fd */
	fd = dup(lttng_userspace_probe_location_function_get_binary_fd(location));
	if (fd == -1) {
		goto free_function_name;
	}

	/*
	 * Duplicate probe location method fields
	 */
	lookup_type = lttng_userspace_probe_location_lookup_method_get_type(
						location->lookup_method);
	switch (lookup_type) {
	case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF:
		lookup_method =
			lttng_userspace_probe_location_lookup_method_function_name_elf_copy(
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
							binary_path, function_name, lookup_method, true);

	if (!new_location) {
		goto destroy_lookup_method;
	}

	/* Set the duplicated fd to the new probe_location */
	if (lttng_userspace_probe_location_function_set_binary_fd(new_location, fd) < 0) {
		goto destroy_probe_location;
	}

end:
	return new_location;

destroy_probe_location:
	lttng_userspace_probe_location_destroy(new_location);
destroy_lookup_method:
	lttng_userspace_probe_location_lookup_method_destroy(lookup_method);
close_fd:
	if (close(fd) < 0) {
		PERROR("close");
	}
free_function_name:
	free(function_name);
free_binary_path:
	free(binary_path);
error:
	new_location = NULL;
	goto end;
}

const char *lttng_userspace_probe_location_function_get_binary_path(
		struct lttng_userspace_probe_location *location)
{
	const char *ret = NULL;
	struct lttng_userspace_probe_location_function *function_location;

	if (!location || lttng_userspace_probe_location_get_type(location) !=
			LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION) {
		goto end;
	}

	function_location = container_of(location,
		struct lttng_userspace_probe_location_function,
			parent);
	ret = function_location->binary_path;
end:
	return ret;
}

const char *lttng_userspace_probe_location_function_get_function_name(
		struct lttng_userspace_probe_location *location)
{
	const char *ret = NULL;
	struct lttng_userspace_probe_location_function *function_location;

	if (!location || lttng_userspace_probe_location_get_type(location) !=
			LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION) {
		goto end;
	}

	function_location = container_of(location,
		struct lttng_userspace_probe_location_function, parent);
	ret = function_location->function_name;
end:
	return ret;
}

int lttng_userspace_probe_location_function_get_binary_fd(
		struct lttng_userspace_probe_location *location)
{
	int ret = -1;
	struct lttng_userspace_probe_location_function *function_location;

	if (!location || lttng_userspace_probe_location_get_type(location) !=
			LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION) {
		goto end;
	}

	function_location = container_of(location,
		struct lttng_userspace_probe_location_function, parent);
	ret = function_location->binary_fd;
end:
	return ret;
}

struct lttng_userspace_probe_location_lookup_method *
lttng_userspace_probe_location_function_get_lookup_method(
		struct lttng_userspace_probe_location *location)
{
	struct lttng_userspace_probe_location_lookup_method *ret = NULL;

	if (!location || lttng_userspace_probe_location_get_type(location) !=
			LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION) {
		goto end;
	}

	ret = location->lookup_method;
end:
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
		struct lttng_userspace_probe_location *location,
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

LTTNG_HIDDEN
int lttng_userspace_probe_location_lookup_method_elf_set_run_as_ids(
			struct lttng_userspace_probe_location_lookup_method *lookup,
			uid_t uid, gid_t gid)
{
	int ret;
	struct lttng_userspace_probe_location_lookup_method_elf *lookup_elf = NULL;

	if (!lookup) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	switch (lttng_userspace_probe_location_lookup_method_get_type(lookup)) {
	case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF:
		break;
	default:
		/* Invalid probe location lookup method. */
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	lookup_elf = container_of(lookup,
				struct lttng_userspace_probe_location_lookup_method_elf, parent);

	lookup_elf->run_as_uid = uid;
	lookup_elf->run_as_gid = gid;
	ret = 0;
end:
	return ret;
}

LTTNG_HIDDEN
int lttng_userspace_probe_location_lookup_method_elf_get_run_as_ids(
			struct lttng_userspace_probe_location_lookup_method *lookup,
			uid_t *uid, gid_t *gid)
{
	int ret;
	struct lttng_userspace_probe_location_lookup_method_elf *lookup_elf = NULL;

	if (!lookup) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}
	switch (lttng_userspace_probe_location_lookup_method_get_type(lookup)) {
	case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF:
		break;
	default:
		/* Invalid probe location lookup method. */
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	lookup_elf = container_of(lookup,
				struct lttng_userspace_probe_location_lookup_method_elf, parent);
	*uid = lookup_elf->run_as_uid;
	*gid = lookup_elf->run_as_gid;
	ret = 0;

end:
	return ret;
}
LTTNG_HIDDEN
int lttng_userspace_probe_location_serialize(
		struct lttng_userspace_probe_location *location,
		struct lttng_dynamic_buffer *buffer,
		int *binary_fd)
{
	int ret, buffer_use = 0;
	struct lttng_userspace_probe_location_comm location_generic_comm;

	if (!location) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	location_generic_comm.type = (int8_t) location->type;
	if (buffer) {
		ret = lttng_dynamic_buffer_append(buffer, &location_generic_comm,
				sizeof(location_generic_comm));
		if (ret) {
			goto end;
		}
	}
	buffer_use += sizeof(location_generic_comm);

	switch (lttng_userspace_probe_location_get_type(location))
	{
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION:
		ret = lttng_userspace_probe_location_function_serialize(
				location, buffer, binary_fd);
		break;
	default:
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
	int ret = 0;
	struct lttng_userspace_probe_location_function_comm *location_function_comm =
			(struct lttng_userspace_probe_location_function_comm *) buffer->data;
	const size_t expected_size = sizeof(*location_function_comm) +
			location_function_comm->function_name_len +
			location_function_comm->binary_path_len;
	const char *function_name_src, *binary_path_src;
	char *function_name = NULL, *binary_path = NULL;

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

	function_name = strdup(function_name_src);
	binary_path = strdup(binary_path_src);

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
int lttng_userspace_probe_location_lookup_method_create_from_buffer(
		struct lttng_buffer_view *buffer,
		struct lttng_userspace_probe_location_lookup_method **lookup_method)
{
	int ret;
	struct lttng_userspace_probe_location_lookup_method_comm *lookup_comm;
	enum lttng_userspace_probe_location_lookup_method_type type;

	assert(buffer);
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
		*lookup_method = lttng_userspace_probe_location_lookup_method_function_name_elf_create();
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
	int ret;
	struct lttng_userspace_probe_location_comm *probe_location_comm;
	enum lttng_userspace_probe_location_type type;
	struct lttng_buffer_view lookup_method_view;
	int consumed = 0;
	struct lttng_userspace_probe_location_lookup_method *lookup_method =
			NULL;

	assert(buffer);
	assert(location);

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
			goto end;
		}
	}

	function_location->binary_fd = binary_fd;
end:
	return ret;
}

LTTNG_HIDDEN
int lttng_userspace_probe_location_flatten(
		struct lttng_userspace_probe_location *location,
		struct lttng_dynamic_buffer *buffer)
{
	int ret;
	int storage_needed = 0;
	struct lttng_userspace_probe_location_function *probe_function;
	struct lttng_userspace_probe_location_function flat_probe;
	struct lttng_userspace_probe_location_lookup_method_elf flat_lookup_method;
	size_t function_name_len, binary_path_len;
	char *flat_probe_start;
	size_t padding_needed = 0;

	if (!location) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	/* Only types currently supported. */
	if (location->type != LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}
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

LTTNG_HIDDEN
struct lttng_userspace_probe_location *
lttng_userspace_probe_location_copy(struct lttng_userspace_probe_location *location)
{
	struct lttng_userspace_probe_location *new_location = NULL;
	enum lttng_userspace_probe_location_type type;

	assert(location);

	type = lttng_userspace_probe_location_get_type(location);
	switch (type) {
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION:
		new_location =
			lttng_userspace_probe_location_function_copy(location);
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
