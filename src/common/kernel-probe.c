/*
 * Copyright (C) 2020 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "lttng/lttng-error.h"
#include <common/error.h>
#include <common/hashtable/hashtable.h>
#include <common/hashtable/utils.h>
#include <common/macros.h>
#include <common/mi-lttng.h>
#include <common/payload-view.h>
#include <common/payload.h>
#include <fcntl.h>
#include <lttng/constant.h>
#include <lttng/kernel-probe-internal.h>
#include <lttng/kernel-probe.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/unistd.h>

static
int lttng_kernel_probe_location_address_serialize(
		const struct lttng_kernel_probe_location *location,
		struct lttng_payload *payload);

static
int lttng_kernel_probe_location_symbol_serialize(
		const struct lttng_kernel_probe_location *location,
		struct lttng_payload *payload);

static
bool lttng_kernel_probe_location_address_is_equal(
		const struct lttng_kernel_probe_location *a,
		const struct lttng_kernel_probe_location *b);

static
bool lttng_kernel_probe_location_symbol_is_equal(
		const struct lttng_kernel_probe_location *a,
		const struct lttng_kernel_probe_location *b);

static
unsigned long lttng_kernel_probe_location_address_hash(
		const struct lttng_kernel_probe_location *location);

static
unsigned long lttng_kernel_probe_location_symbol_hash(
		const struct lttng_kernel_probe_location *location);

static
enum lttng_error_code lttng_kernel_probe_location_address_mi_serialize(
		const struct lttng_kernel_probe_location *location,
		struct mi_writer *writer);

static
enum lttng_error_code lttng_kernel_probe_location_symbol_mi_serialize(
		const struct lttng_kernel_probe_location *location,
		struct mi_writer *writer);

enum lttng_kernel_probe_location_type lttng_kernel_probe_location_get_type(
		const struct lttng_kernel_probe_location *location)
{
	return location ? location->type :
			LTTNG_KERNEL_PROBE_LOCATION_TYPE_UNKNOWN;
}

static
void lttng_kernel_probe_location_address_destroy(
		struct lttng_kernel_probe_location *location)
{
	LTTNG_ASSERT(location);
	free(location);
}

static
void lttng_kernel_probe_location_symbol_destroy(
		struct lttng_kernel_probe_location *location)
{
	struct lttng_kernel_probe_location_symbol *location_symbol = NULL;

	LTTNG_ASSERT(location);

	location_symbol = container_of(location,
			struct lttng_kernel_probe_location_symbol,
			parent);

	LTTNG_ASSERT(location_symbol);

	free(location_symbol->symbol_name);
	free(location);
}

void lttng_kernel_probe_location_destroy(
		struct lttng_kernel_probe_location *location)
{
	if (!location) {
		return;
	}

	switch (location->type) {
	case LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS:
		lttng_kernel_probe_location_address_destroy(location);
		break;
	case LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET:
		lttng_kernel_probe_location_symbol_destroy(location);
		break;
	default:
		abort();
	}
}

struct lttng_kernel_probe_location *
lttng_kernel_probe_location_address_create(uint64_t address)
{
	struct lttng_kernel_probe_location *ret = NULL;
	struct lttng_kernel_probe_location_address *location;

	location = zmalloc(sizeof(*location));
	if (!location) {
		PERROR("Error allocating userspace probe location.");
		goto end;
	}

	location->address = address;

	ret = &location->parent;
	ret->type = LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS;
	ret->equal = lttng_kernel_probe_location_address_is_equal;
	ret->serialize = lttng_kernel_probe_location_address_serialize;
	ret->hash = lttng_kernel_probe_location_address_hash;
	ret->mi_serialize = lttng_kernel_probe_location_address_mi_serialize;

end:
	return ret;
}

struct lttng_kernel_probe_location *
lttng_kernel_probe_location_symbol_create(const char *symbol_name,
		uint64_t offset)
{
	char *symbol_name_copy = NULL;
	struct lttng_kernel_probe_location *ret = NULL;
	struct lttng_kernel_probe_location_symbol *location;

	if (!symbol_name || strlen(symbol_name) >= LTTNG_SYMBOL_NAME_LEN) {
		goto error;
	}

	symbol_name_copy = strdup(symbol_name);
	if (!symbol_name_copy) {
		PERROR("Failed to copy symbol name '%s'", symbol_name);
		goto error;
	}

	location = zmalloc(sizeof(*location));
	if (!location) {
		PERROR("Failed to allocate kernel symbol probe location");
		goto error;
	}

	location->symbol_name = symbol_name_copy;
	location->offset = offset;

	ret = &location->parent;
	ret->type = LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET;
	ret->equal = lttng_kernel_probe_location_symbol_is_equal;
	ret->serialize = lttng_kernel_probe_location_symbol_serialize;
	ret->hash = lttng_kernel_probe_location_symbol_hash;
	ret->mi_serialize = lttng_kernel_probe_location_symbol_mi_serialize;
	goto end;

error:
	free(symbol_name_copy);
end:
	return ret;
}

enum lttng_kernel_probe_location_status
lttng_kernel_probe_location_address_get_address(
		const struct lttng_kernel_probe_location *location,
		uint64_t *offset)
{
	enum lttng_kernel_probe_location_status ret =
			LTTNG_KERNEL_PROBE_LOCATION_STATUS_OK;
	struct lttng_kernel_probe_location_address *address_location;

	LTTNG_ASSERT(offset);

	if (!location || lttng_kernel_probe_location_get_type(location) !=
			LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS) {
		ERR("Invalid argument(s) passed to '%s'", __FUNCTION__);
		ret = LTTNG_KERNEL_PROBE_LOCATION_STATUS_INVALID;
		goto end;
	}

	address_location = container_of(location,
			struct lttng_kernel_probe_location_address, parent);
	*offset = address_location->address;
end:
	return ret;
}

const char *lttng_kernel_probe_location_symbol_get_name(
		const struct lttng_kernel_probe_location *location)
{
	const char *ret = NULL;
	struct lttng_kernel_probe_location_symbol *symbol_location;

	if (!location || lttng_kernel_probe_location_get_type(location) !=
			LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET) {
		ERR("Invalid argument(s) passed to '%s'", __FUNCTION__);
		goto end;
	}

	symbol_location = container_of(location,
			struct lttng_kernel_probe_location_symbol, parent);
	ret = symbol_location->symbol_name;
end:
	return ret;
}

enum lttng_kernel_probe_location_status
lttng_kernel_probe_location_symbol_get_offset(
		const struct lttng_kernel_probe_location *location,
		uint64_t *offset)
{
	enum lttng_kernel_probe_location_status ret =
			LTTNG_KERNEL_PROBE_LOCATION_STATUS_OK;
	struct lttng_kernel_probe_location_symbol *symbol_location;

	LTTNG_ASSERT(offset);

	if (!location || lttng_kernel_probe_location_get_type(location) !=
			LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET) {
		ERR("Invalid argument(s) passed to '%s'", __FUNCTION__);
		ret = LTTNG_KERNEL_PROBE_LOCATION_STATUS_INVALID;
		goto end;
	}

	symbol_location = container_of(location,
			struct lttng_kernel_probe_location_symbol, parent);
	*offset = symbol_location->offset;
end:
	return ret;
}

static
int lttng_kernel_probe_location_symbol_serialize(
		const struct lttng_kernel_probe_location *location,
		struct lttng_payload *payload)
{
	int ret;
	size_t symbol_name_len;
	size_t original_payload_size;
	struct lttng_kernel_probe_location_symbol *location_symbol;
	struct lttng_kernel_probe_location_symbol_comm location_symbol_comm;

	if (!location || !payload) {
		ERR("Invalid argument(s) passed to '%s'", __FUNCTION__);
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	LTTNG_ASSERT(lttng_kernel_probe_location_get_type(location) ==
			LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET);

	original_payload_size = payload->buffer.size;
	location_symbol = container_of(location,
			struct lttng_kernel_probe_location_symbol, parent);

	if (!location_symbol->symbol_name) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	symbol_name_len = strlen(location_symbol->symbol_name);
	if (symbol_name_len == 0) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	location_symbol_comm.symbol_len = symbol_name_len + 1;
	location_symbol_comm.offset = location_symbol->offset;

	ret = lttng_dynamic_buffer_append(&payload->buffer,
			&location_symbol_comm, sizeof(location_symbol_comm));
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = lttng_dynamic_buffer_append(&payload->buffer,
			location_symbol->symbol_name,
			location_symbol_comm.symbol_len);
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = (int) (payload->buffer.size - original_payload_size);
end:
	return ret;
}

static
int lttng_kernel_probe_location_address_serialize(
		const struct lttng_kernel_probe_location *location,
		struct lttng_payload *payload)
{
	int ret;
	size_t original_payload_size;
	struct lttng_kernel_probe_location_address *location_address;
	struct lttng_kernel_probe_location_address_comm location_address_comm;

	LTTNG_ASSERT(location);
	LTTNG_ASSERT(lttng_kernel_probe_location_get_type(location) ==
			LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS);

	original_payload_size = payload->buffer.size;
	location_address = container_of(location,
			struct lttng_kernel_probe_location_address,
			parent);

	location_address_comm.address = location_address->address;

	ret = lttng_dynamic_buffer_append(&payload->buffer,
			&location_address_comm,
			sizeof(location_address_comm));
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = (int) (payload->buffer.size - original_payload_size);
end:
	return ret;
}

LTTNG_HIDDEN
int lttng_kernel_probe_location_serialize(
		const struct lttng_kernel_probe_location *location,
		struct lttng_payload *payload)
{
	int ret;
	size_t original_payload_size;
	struct lttng_kernel_probe_location_comm location_generic_comm = {};

	if (!location || !payload) {
		ERR("Invalid argument(s) passed to '%s'", __FUNCTION__);
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	original_payload_size = payload->buffer.size;
	location_generic_comm.type = (int8_t) location->type;
	ret = lttng_dynamic_buffer_append(&payload->buffer,
			&location_generic_comm,
			sizeof(location_generic_comm));
	if (ret) {
		goto end;
	}

	ret = location->serialize(location, payload);
	if (ret < 0) {
		goto end;
	}

	ret = (int) (payload->buffer.size - original_payload_size);
end:
	return ret;
}

static
int lttng_kernel_probe_location_symbol_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_kernel_probe_location **location)
{
	struct lttng_kernel_probe_location_symbol_comm *location_symbol_comm;
	const char *symbol_name_src;
	ssize_t ret = 0;
	size_t expected_size;

	LTTNG_ASSERT(location);

	if (view->buffer.size < sizeof(*location_symbol_comm)) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	location_symbol_comm =
			(typeof(location_symbol_comm)) view->buffer.data;

	expected_size = sizeof(*location_symbol_comm) +
			location_symbol_comm->symbol_len;

	if (view->buffer.size < expected_size) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	symbol_name_src = view->buffer.data + sizeof(*location_symbol_comm);

	if (!lttng_buffer_view_contains_string(&view->buffer, symbol_name_src,
			location_symbol_comm->symbol_len)) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	*location = lttng_kernel_probe_location_symbol_create(
			symbol_name_src, location_symbol_comm->offset);
	if (!(*location)) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = (ssize_t) expected_size;
end:
	return ret;
}

static
ssize_t lttng_kernel_probe_location_address_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_kernel_probe_location **location)
{
	struct lttng_kernel_probe_location_address_comm *location_address_comm;
	ssize_t ret = 0;
	size_t expected_size;

	LTTNG_ASSERT(location);

	expected_size = sizeof(*location_address_comm);

	if (view->buffer.size < expected_size) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	location_address_comm =
			(typeof(location_address_comm)) view->buffer.data;

	*location = lttng_kernel_probe_location_address_create(location_address_comm->address);
	if (!(*location)) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = (size_t) expected_size;
end:
	return ret;
}

LTTNG_HIDDEN
ssize_t lttng_kernel_probe_location_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_kernel_probe_location **location)
{
	enum lttng_kernel_probe_location_type type;
	ssize_t consumed = 0;
	ssize_t ret;
	const struct lttng_kernel_probe_location_comm *probe_location_comm;
	const struct lttng_payload_view probe_location_comm_view =
			lttng_payload_view_from_view(
					view, 0, sizeof(*probe_location_comm));

	LTTNG_ASSERT(view);
	LTTNG_ASSERT(location);

	if (!lttng_payload_view_is_valid(&probe_location_comm_view)) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	probe_location_comm = (typeof(probe_location_comm)) probe_location_comm_view.buffer.data;
	type = (enum lttng_kernel_probe_location_type) probe_location_comm->type;
	consumed += sizeof(*probe_location_comm);

	switch (type) {
	case LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET:
	{
		struct lttng_payload_view location_view =
				lttng_payload_view_from_view(
						view, consumed, -1);

		ret = lttng_kernel_probe_location_symbol_create_from_payload(
				&location_view, location);
		break;
	}
	case LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS:
	{
		struct lttng_payload_view location_view =
				lttng_payload_view_from_view(view, consumed, -1);

		ret = lttng_kernel_probe_location_address_create_from_payload(
				&location_view, location);
		break;
	}
	default:
		ret = -LTTNG_ERR_INVALID;
		break;
	}

	if (ret < 0) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret += consumed;

end:
	return ret;
}

static
unsigned long lttng_kernel_probe_location_address_hash(
		const struct lttng_kernel_probe_location *location)
{
	unsigned long hash = hash_key_ulong(
			(void *) LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS,
			lttng_ht_seed);
	struct lttng_kernel_probe_location_address *address_location =
			container_of(location, typeof(*address_location),
				parent);

	hash ^= hash_key_u64(&address_location->address, lttng_ht_seed);

	return hash;
}

static
bool lttng_kernel_probe_location_address_is_equal(
		const struct lttng_kernel_probe_location *_a,
		const struct lttng_kernel_probe_location *_b)
{
	bool is_equal = false;
	struct lttng_kernel_probe_location_address *a, *b;

	a = container_of(_a, struct lttng_kernel_probe_location_address,
			parent);
	b = container_of(_b, struct lttng_kernel_probe_location_address,
			parent);

	if (a->address != b->address) {
		goto end;
	}

	is_equal = true;

end:
	return is_equal;
}

static
unsigned long lttng_kernel_probe_location_symbol_hash(
		const struct lttng_kernel_probe_location *location)
{
	unsigned long hash = hash_key_ulong(
			(void *) LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET,
			lttng_ht_seed);
	struct lttng_kernel_probe_location_symbol *symbol_location =
			container_of(location, typeof(*symbol_location),
				parent);

	hash ^= hash_key_str(symbol_location->symbol_name, lttng_ht_seed);
	hash ^= hash_key_u64(&symbol_location->offset, lttng_ht_seed);

	return hash;
}

static
bool lttng_kernel_probe_location_symbol_is_equal(
		const struct lttng_kernel_probe_location *_a,
		const struct lttng_kernel_probe_location *_b)
{
	bool is_equal = false;
	struct lttng_kernel_probe_location_symbol *a, *b;

	a = container_of(_a, struct lttng_kernel_probe_location_symbol,
			parent);
	b = container_of(_b, struct lttng_kernel_probe_location_symbol,
			parent);

	LTTNG_ASSERT(a->symbol_name);
	LTTNG_ASSERT(b->symbol_name);
	if (strcmp(a->symbol_name, b->symbol_name)) {
		goto end;
	}

	if (a->offset != b->offset) {
		goto end;
	}

	is_equal = true;

end:
	return is_equal;
}

LTTNG_HIDDEN
bool lttng_kernel_probe_location_is_equal(
		const struct lttng_kernel_probe_location *a,
		const struct lttng_kernel_probe_location *b)
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

	is_equal = a->equal ? a->equal(a, b) : true;
end:
	return is_equal;
}

static struct lttng_kernel_probe_location *
lttng_kernel_probe_location_symbol_copy(
		const struct lttng_kernel_probe_location *location)
{
	struct lttng_kernel_probe_location *new_location = NULL;
	struct lttng_kernel_probe_location_symbol *symbol_location;
	enum lttng_kernel_probe_location_status status;
	const char *symbol_name = NULL;
	uint64_t offset;

	LTTNG_ASSERT(location);
	LTTNG_ASSERT(location->type == LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET);
	symbol_location = container_of(
			location, typeof(*symbol_location), parent);

	 /* Get probe location offset */
	status = lttng_kernel_probe_location_symbol_get_offset(location, &offset);
	if (status != LTTNG_KERNEL_PROBE_LOCATION_STATUS_OK) {
		ERR("Get kernel probe location offset failed.");
		goto error;
	}

	symbol_name = lttng_kernel_probe_location_symbol_get_name(location);
	if (!symbol_name) {
		ERR("Kernel probe symbol name is NULL.");
		goto error;
	}

	/* Create the probe_location */
	new_location = lttng_kernel_probe_location_symbol_create(
			symbol_name, offset);

	goto end;

error:
	new_location = NULL;
end:
	return new_location;
}
static struct lttng_kernel_probe_location *
lttng_kernel_probe_location_address_copy(
		const struct lttng_kernel_probe_location *location)
{
	struct lttng_kernel_probe_location *new_location = NULL;
	struct lttng_kernel_probe_location_address *address_location;
	enum lttng_kernel_probe_location_status status;
	uint64_t address;

	LTTNG_ASSERT(location);
	LTTNG_ASSERT(location->type == LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS);
	address_location = container_of(
			location, typeof(*address_location), parent);


	 /* Get probe location fields */
	status = lttng_kernel_probe_location_address_get_address(location, &address);
	if (status != LTTNG_KERNEL_PROBE_LOCATION_STATUS_OK) {
		ERR("Get kernel probe address failed.");
		goto error;
	}

	/* Create the probe_location */
	new_location = lttng_kernel_probe_location_address_create(address);

	goto end;

error:
	new_location = NULL;
end:
	return new_location;
}

LTTNG_HIDDEN
struct lttng_kernel_probe_location *lttng_kernel_probe_location_copy(
		const struct lttng_kernel_probe_location *location)
{
	struct lttng_kernel_probe_location *new_location = NULL;
	enum lttng_kernel_probe_location_type type;

	if (!location) {
		goto err;
	}

	type = lttng_kernel_probe_location_get_type(location);
	switch (type) {
	case LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS:
		new_location =
			lttng_kernel_probe_location_address_copy(location);
		if (!new_location) {
			goto err;
		}
		break;
	case LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET:
		new_location =
			lttng_kernel_probe_location_symbol_copy(location);
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
unsigned long lttng_kernel_probe_location_hash(
	const struct lttng_kernel_probe_location *location)
{
	return location->hash(location);
}

static
enum lttng_error_code lttng_kernel_probe_location_address_mi_serialize(
		const struct lttng_kernel_probe_location *location,
		struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;
	enum lttng_kernel_probe_location_status status;
	uint64_t address;

	LTTNG_ASSERT(location);
	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(location->type == LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS);

	status = lttng_kernel_probe_location_address_get_address(
			location, &address);
	LTTNG_ASSERT(status == LTTNG_KERNEL_PROBE_LOCATION_STATUS_OK);

	/* Open kernel probe location address element. */
	ret = mi_lttng_writer_open_element(
			writer, mi_lttng_element_kernel_probe_location_address);
	if (ret) {
		goto mi_error;
	}

	ret = mi_lttng_writer_write_element_unsigned_int(writer,
			mi_lttng_element_kernel_probe_location_address_address,
			address);
	if (ret) {
		goto mi_error;
	}

	/* Close kernel probe location address element. */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto mi_error;
	}

	ret_code = LTTNG_OK;
	goto end;

mi_error:
	ret_code = LTTNG_ERR_MI_IO_FAIL;
end:
	return ret_code;
}

static
enum lttng_error_code lttng_kernel_probe_location_symbol_mi_serialize(
		const struct lttng_kernel_probe_location *location,
		struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;
	enum lttng_kernel_probe_location_status status;
	const char *name = NULL;
	uint64_t offset;

	LTTNG_ASSERT(location);
	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(location->type ==
			LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET);

	name = lttng_kernel_probe_location_symbol_get_name(location);
	LTTNG_ASSERT(name);

	status = lttng_kernel_probe_location_symbol_get_offset(
			location, &offset);
	LTTNG_ASSERT(status == LTTNG_KERNEL_PROBE_LOCATION_STATUS_OK);

	/* Open kernel probe location symbol offset element. */
	ret = mi_lttng_writer_open_element(writer,
			mi_lttng_element_kernel_probe_location_symbol_offset);
	if (ret) {
		goto mi_error;
	}

	/* Name. */
	ret = mi_lttng_writer_write_element_string(writer,
			mi_lttng_element_kernel_probe_location_symbol_offset_name,
			name);
	if (ret) {
		goto mi_error;
	}

	/* Offset. */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
			mi_lttng_element_kernel_probe_location_symbol_offset_offset,
			offset);
	if (ret) {
		goto mi_error;
	}

	/* Close kernel probe location symbol offset element. */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto mi_error;
	}

	ret_code = LTTNG_OK;
	goto end;

mi_error:
	ret_code = LTTNG_ERR_MI_IO_FAIL;
end:
	return ret_code;
}

LTTNG_HIDDEN
enum lttng_error_code lttng_kernel_probe_location_mi_serialize(
		const struct lttng_kernel_probe_location *location,
		struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;

	LTTNG_ASSERT(location);
	LTTNG_ASSERT(writer);

	/* Open kernel probe location element. */
	ret = mi_lttng_writer_open_element(
			writer, mi_lttng_element_kernel_probe_location);
	if (ret) {
		goto mi_error;
	}

	/* Serialize the location sub type. */
	ret_code = location->mi_serialize(location, writer);
	if (ret_code != LTTNG_OK) {
		goto end;
	}

	/* Close kernel probe location element. */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto mi_error;
	}

	ret_code = LTTNG_OK;
	goto end;

mi_error:
	ret_code = LTTNG_ERR_MI_IO_FAIL;
end:
	return ret_code;
}
