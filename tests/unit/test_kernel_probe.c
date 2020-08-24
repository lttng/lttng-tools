/*
 * Unit tests for the kernel probe location API.
 *
 * Copyright (C) 2020 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <tap/tap.h>

#include <common/payload-view.h>
#include <common/payload.h>
#include <lttng/kernel-probe-internal.h>
#include <lttng/kernel-probe.h>

/* For error.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose;
int lttng_opt_mi;

#define NUM_TESTS 24

static void test_kernel_probe_location_address(void)
{
	struct lttng_kernel_probe_location *location = NULL;
	struct lttng_kernel_probe_location *location_from_buffer = NULL;
	enum lttng_kernel_probe_location_status status;
	enum lttng_kernel_probe_location_type type;
	uint64_t address = 50, _address;
	struct lttng_payload payload;

	diag("Testing kernel probe location address");

	lttng_payload_init(&payload);

	location = lttng_kernel_probe_location_address_create(address);
	ok(location, "Location object");

	type = lttng_kernel_probe_location_get_type(location);
	ok(LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS == type,
			"Location type got %d expected %d", type,
			LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS);

	status = lttng_kernel_probe_location_address_get_address(
			location, &_address);
	ok(status == LTTNG_KERNEL_PROBE_LOCATION_STATUS_OK, "Getting address");
	ok(address == _address,
			"Address is equal. Got %" PRIu64 " expected %" PRIu64,
			_address, address);

	ok(lttng_kernel_probe_location_serialize(location, &payload) > 0,
			"Serializing");
	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(
						&payload, 0, -1);
		ok(lttng_kernel_probe_location_create_from_payload(
				   &view, &location_from_buffer) > 0,
				"Deserializing");
	}

	type = lttng_kernel_probe_location_get_type(location_from_buffer);
	ok(LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS == type,
			"Location from buffer type got %d expected %d", type,
			LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS);

	status = lttng_kernel_probe_location_address_get_address(
			location_from_buffer, &_address);
	ok(status == LTTNG_KERNEL_PROBE_LOCATION_STATUS_OK, "Getting address");
	ok(address == _address,
			"Address from buffer is equal. Got %" PRIu64
			" expected %" PRIu64,
			_address, address);

	ok(lttng_kernel_probe_location_is_equal(location, location_from_buffer),
			"serialized and from buffer are equal");

	lttng_payload_reset(&payload);
	lttng_kernel_probe_location_destroy(location);
	lttng_kernel_probe_location_destroy(location_from_buffer);
}

static void test_kernel_probe_location_symbol(void)
{
	struct lttng_kernel_probe_location *location = NULL;
	struct lttng_kernel_probe_location *location_from_buffer = NULL;
	enum lttng_kernel_probe_location_status status;
	enum lttng_kernel_probe_location_type type;
	uint64_t offset = 50, _offset;
	const char *symbol = "Une_bonne", *_symbol;
	struct lttng_payload payload;

	diag("Testing kernel probe location symbol");

	lttng_payload_init(&payload);

	location = lttng_kernel_probe_location_symbol_create(symbol, offset);
	ok(location, "Location object");

	type = lttng_kernel_probe_location_get_type(location);
	ok(LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET == type,
			"Location type got %d expected %d", type,
			LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET);

	_symbol = lttng_kernel_probe_location_symbol_get_name(location);
	ok(_symbol, "Getting symbol name");
	ok(!strncmp(symbol, _symbol, strlen(symbol)),
			"Symbol name is equal. Got %s, expected %s", _symbol,
			symbol);

	status = lttng_kernel_probe_location_symbol_get_offset(
			location, &_offset);
	ok(status == LTTNG_KERNEL_PROBE_LOCATION_STATUS_OK, "Getting offset");
	ok(offset == _offset,
			"Offset is equal. Got %" PRIu64 " expected %" PRIu64,
			_offset, offset);

	ok(lttng_kernel_probe_location_serialize(location, &payload) > 0,
			"Serializing");
	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(
						&payload, 0, -1);
		ok(lttng_kernel_probe_location_create_from_payload(
				   &view, &location_from_buffer) > 0,
				"Deserializing");
	}

	type = lttng_kernel_probe_location_get_type(location_from_buffer);
	ok(LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET == type,
			"Location from buffer type got %d expected %d", type,
			LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET);

	_symbol = lttng_kernel_probe_location_symbol_get_name(
			location_from_buffer);
	ok(_symbol, "Getting symbol name");
	ok(!strncmp(symbol, _symbol, strlen(symbol)),
			"Symbol name is equal. Got %s, expected %s", _symbol,
			symbol);

	status = lttng_kernel_probe_location_symbol_get_offset(
			location_from_buffer, &_offset);
	ok(status == LTTNG_KERNEL_PROBE_LOCATION_STATUS_OK, "Getting offset");
	ok(offset == _offset,
			"Offset is equal. Got %" PRIu64 " expected %" PRIu64,
			_offset, offset);

	ok(lttng_kernel_probe_location_is_equal(location, location_from_buffer),
			"serialized and from buffer are equal");

	lttng_payload_reset(&payload);
	lttng_kernel_probe_location_destroy(location);
	lttng_kernel_probe_location_destroy(location_from_buffer);
}

int main(int argc, const char *argv[])
{
	plan_tests(NUM_TESTS);
	test_kernel_probe_location_address();
	test_kernel_probe_location_symbol();
	return exit_status();
}
