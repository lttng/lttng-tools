/*
 * Unit tests for the notification API.
 *
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
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
#include <lttng/domain.h>
#include <lttng/event-rule/kprobe-internal.h>
#include <lttng/event-rule/kprobe.h>
#include <lttng/event-rule/syscall-internal.h>
#include <lttng/event-rule/syscall.h>
#include <lttng/event-rule/tracepoint-internal.h>
#include <lttng/event-rule/tracepoint.h>
#include <lttng/event-rule/uprobe-internal.h>
#include <lttng/event-rule/uprobe.h>
#include <lttng/event.h>
#include <lttng/kernel-probe-internal.h>
#include <lttng/kernel-probe.h>
#include <lttng/userspace-probe-internal.h>
#include <lttng/userspace-probe.h>

/* For error.h. */
int lttng_opt_quiet = 1;
int lttng_opt_verbose;
int lttng_opt_mi;

#define NUM_TESTS 187

struct tracepoint_test {
	enum lttng_domain_type type;
	bool support_exclusion;
};

static
void test_event_rule_tracepoint_by_domain(const struct tracepoint_test *test)
{
	int ret;
	unsigned int count;
	struct lttng_event_rule *tracepoint = NULL;
	struct lttng_event_rule *tracepoint_from_buffer = NULL;
	enum lttng_event_rule_status status;
	enum lttng_domain_type domain_type, type;
	enum lttng_loglevel_type log_level_type;
	const char *pattern="my_event_*";
	const char *filter="msg_id == 23 && size >= 2048";
	const char *tmp;
	const char *exclusions[] = {"my_event_test1", "my_event_test2" ,"my_event_test3"};
	struct lttng_payload payload;

	type = test->type;
	diag("Testing domain %d.", type);

	lttng_payload_init(&payload);

	tracepoint = lttng_event_rule_tracepoint_create(type);
	ok(tracepoint, "tracepoint object.");

	status = lttng_event_rule_tracepoint_get_domain_type(tracepoint, &domain_type);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK, "get tracepoint domain.");
	ok(domain_type == type, "domain type got %d expected %d.", domain_type, type);

	status = lttng_event_rule_tracepoint_set_pattern(tracepoint, pattern);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK, "setting pattern.");
	status = lttng_event_rule_tracepoint_get_pattern(tracepoint, &tmp);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK, "getting pattern.");
	ok(!strncmp(pattern, tmp, strlen(pattern)), "pattern is equal.");

	status = lttng_event_rule_tracepoint_set_filter(tracepoint, filter);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK, "setting filter.");
	status = lttng_event_rule_tracepoint_get_filter(tracepoint, &tmp);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK, "getting filter.");
	ok(!strncmp(filter, tmp, strlen(filter)), "filter is equal.");

	status = lttng_event_rule_tracepoint_set_log_level_all(tracepoint);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK, "setting all log level.");
	status = lttng_event_rule_tracepoint_get_log_level_type(tracepoint, &log_level_type);
	ok(log_level_type == LTTNG_EVENT_LOGLEVEL_ALL, "getting loglevel type all.");
	status = lttng_event_rule_tracepoint_get_log_level(tracepoint, &ret);
	ok(status == LTTNG_EVENT_RULE_STATUS_UNSET, "get unset loglevel value.");

	status = lttng_event_rule_tracepoint_set_log_level(tracepoint, LTTNG_LOGLEVEL_INFO);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK, "setting single loglevel.");
	status = lttng_event_rule_tracepoint_get_log_level_type(tracepoint, &log_level_type);
	ok(log_level_type == LTTNG_EVENT_LOGLEVEL_SINGLE, "getting loglevel type single.");
	status = lttng_event_rule_tracepoint_get_log_level(tracepoint, &ret);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK, "get loglevel value.");
	ok(ret == LTTNG_LOGLEVEL_INFO, "loglevel value is equal.");

	status = lttng_event_rule_tracepoint_set_log_level_range_lower_bound(tracepoint, LTTNG_LOGLEVEL_WARNING);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK, "setting range loglevel.");
	status = lttng_event_rule_tracepoint_get_log_level_type(tracepoint, &log_level_type);
	ok(log_level_type == LTTNG_EVENT_LOGLEVEL_RANGE, "getting loglevel type range.");
	status = lttng_event_rule_tracepoint_get_log_level(tracepoint, &ret);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK, "get loglevel value.");
	ok(ret == LTTNG_LOGLEVEL_WARNING, "loglevel valuei is equal.");

	if (test->support_exclusion) {
		int i;

		for (i = 0; i < 3; i++) {
			status = lttng_event_rule_tracepoint_add_exclusion(tracepoint, exclusions[i]);
			ok(status == LTTNG_EVENT_RULE_STATUS_OK, "setting exclusions \"%s\"", exclusions[i]);
		}

		status = lttng_event_rule_tracepoint_get_exclusions_count(tracepoint, &count);
		ok(status == LTTNG_EVENT_RULE_STATUS_OK, "getting exclusion count.");
		ok(count == 3, "count is %d/3", count);

		for (i = 0; i < count; i++) {
			status = lttng_event_rule_tracepoint_get_exclusion_at_index(tracepoint, i, &tmp);
			ok(status == LTTNG_EVENT_RULE_STATUS_OK, "getting exclusion at index %d.", i);
			ok(!strncmp(exclusions[i], tmp, strlen(exclusions[i])), "%s == %s.", tmp, exclusions[i]);
		}
	} else {
		int i;

		for (i = 0; i < 3; i++) {
			status = lttng_event_rule_tracepoint_add_exclusion(tracepoint, exclusions[i]);
			ok(status == LTTNG_EVENT_RULE_STATUS_UNSUPPORTED, "setting exclusions unsupported \"%s\".", exclusions[i]);
		}

		status = lttng_event_rule_tracepoint_get_exclusions_count(tracepoint, &count);
		ok(status == LTTNG_EVENT_RULE_STATUS_OK, "getting exclusion count.");
		ok(count == 0, "count is %d/0", count);
	}

	ok(lttng_event_rule_serialize(tracepoint, &payload) == 0, "Serializing.");

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(
						&payload, 0, -1);

		ok(lttng_event_rule_create_from_payload(
				&view, &tracepoint_from_buffer) > 0,
				"Deserializing.");
	}

	ok(lttng_event_rule_is_equal(tracepoint, tracepoint_from_buffer), "serialized and from buffer are equal.");

	lttng_payload_reset(&payload);
	lttng_event_rule_destroy(tracepoint);
	lttng_event_rule_destroy(tracepoint_from_buffer);
}

static
void test_event_rule_tracepoint(void)
{
	int i;
	struct lttng_event_rule *tracepoint = NULL;
	struct tracepoint_test tests[] = {{LTTNG_DOMAIN_JUL, false},
			{LTTNG_DOMAIN_KERNEL, false},
			{LTTNG_DOMAIN_LOG4J, false},
			{LTTNG_DOMAIN_PYTHON, false},
			{LTTNG_DOMAIN_UST, true}};

	diag("Testing lttng_event_rule_tracepoint.");
	tracepoint = lttng_event_rule_tracepoint_create(LTTNG_DOMAIN_NONE);
	ok(!tracepoint, "Domain type restriction on create.");

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		test_event_rule_tracepoint_by_domain(&tests[i]);
	}
}

static void test_event_rule_syscall(void)
{
	struct lttng_event_rule *syscall = NULL;
	struct lttng_event_rule *syscall_from_buffer = NULL;
	enum lttng_event_rule_status status;
	const char *pattern = "my_event_*";
	const char *filter = "msg_id == 23 && size >= 2048";
	const char *tmp;
	struct lttng_payload payload;

	diag("Event rule syscall.");

	lttng_payload_init(&payload);

	syscall = lttng_event_rule_syscall_create();
	ok(syscall, "syscall object.");

	status = lttng_event_rule_syscall_set_pattern(syscall, pattern);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK, "setting pattern.");
	status = lttng_event_rule_syscall_get_pattern(syscall, &tmp);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK, "getting pattern.");
	ok(!strncmp(pattern, tmp, strlen(pattern)), "pattern is equal.");

	status = lttng_event_rule_syscall_set_filter(syscall, filter);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK, "setting filter.");
	status = lttng_event_rule_syscall_get_filter(syscall, &tmp);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK, "getting filter.");
	ok(!strncmp(filter, tmp, strlen(filter)), "filter is equal.");

	ok(lttng_event_rule_serialize(syscall, &payload) == 0, "Serializing.");

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(
						&payload, 0, -1);

		ok(lttng_event_rule_create_from_payload(
				   &view, &syscall_from_buffer) > 0,
				"Deserializing.");
	}

	ok(lttng_event_rule_is_equal(syscall, syscall_from_buffer),
			"serialized and from buffer are equal.");

	lttng_payload_reset(&payload);
	lttng_event_rule_destroy(syscall);
	lttng_event_rule_destroy(syscall_from_buffer);
}

static void test_event_rule_uprobe(void)
{
	struct lttng_event_rule *uprobe = NULL;
	struct lttng_event_rule *uprobe_from_buffer = NULL;
	struct lttng_userspace_probe_location_lookup_method *lookup_method =
			NULL;
	struct lttng_userspace_probe_location *probe_location = NULL;
	const struct lttng_userspace_probe_location *probe_location_tmp = NULL;
	enum lttng_event_rule_status status;

	const char *probe_name = "my_probe.";
	const char *tmp;
	struct lttng_payload payload;

	diag("Event rule uprobe.");

	lookup_method = lttng_userspace_probe_location_lookup_method_function_elf_create();
	if (!lookup_method) {
		fail("Setup error on userspace probe lookup method creation.");
		goto end;
	}

	probe_location = lttng_userspace_probe_location_function_create(
			"/proc/self/exe",
			"lttng_userspace_probe_location_tracepoint_create",
			lookup_method);
	if (!probe_location) {
		fail("Setup error on userspace probe location creation.");
		goto end;
	}

	/* Ownership transferred to the probe location function object. */
	lookup_method = NULL;

	lttng_payload_init(&payload);

	uprobe = lttng_event_rule_uprobe_create();
	ok(uprobe, "uprobe event rule object creation.");

	status = lttng_event_rule_uprobe_set_location(uprobe, probe_location);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK,
			"Setting uprobe event rule location.");

	status = lttng_event_rule_uprobe_get_location(
			uprobe, &probe_location_tmp);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK,
			"Getting uprobe event rule location.");
	ok(lttng_userspace_probe_location_is_equal(
			   probe_location, probe_location_tmp),
			"Location is equal.");

	status = lttng_event_rule_uprobe_set_name(uprobe, probe_name);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK,
			"Setting uprobe event rule name: %s.", probe_name);
	status = lttng_event_rule_uprobe_get_name(uprobe, &tmp);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK, "Getting uprobe name.");
	ok(!strcmp(probe_name, tmp), "Uprobe name are equal.");

	ok(lttng_event_rule_serialize(uprobe, &payload) == 0, "Serializing.");

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(
						&payload, 0, -1);

		ok(lttng_event_rule_create_from_payload(
				   &view, &uprobe_from_buffer) > 0,
				"Deserializing.");
	}

	ok(lttng_event_rule_is_equal(uprobe, uprobe_from_buffer),
			"serialized and from buffer are equal.");

end:
	lttng_payload_reset(&payload);
	lttng_event_rule_destroy(uprobe);
	lttng_event_rule_destroy(uprobe_from_buffer);
	lttng_userspace_probe_location_destroy(probe_location);
	lttng_userspace_probe_location_lookup_method_destroy(lookup_method);
}

static void test_event_rule_kprobe_by_location(
		const struct lttng_kernel_probe_location *location)
{
	struct lttng_event_rule *kprobe = NULL;
	struct lttng_event_rule *kprobe_from_buffer = NULL;
	enum lttng_event_rule_status status;
	const struct lttng_kernel_probe_location *_location;

	const char *probe_name = "my_probe";
	const char *tmp;
	struct lttng_payload payload;

	diag("Event rule kprobe for location type %d.",
			lttng_kernel_probe_location_get_type(location));

	lttng_payload_init(&payload);

	kprobe = lttng_event_rule_kprobe_create();
	ok(kprobe, "kprobe event rule object creation.");

	status = lttng_event_rule_kprobe_set_location(kprobe, location);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK,
			"Setting kprobe event rule location.");
	status = lttng_event_rule_kprobe_get_location(kprobe, &_location);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK,
			"Getting kprobe event rule location.");
	ok(lttng_kernel_probe_location_is_equal(location, _location), "Locations are equal.");

	status = lttng_event_rule_kprobe_set_name(kprobe, probe_name);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK,
			"Setting kprobe event rule name: %s.", probe_name);
	status = lttng_event_rule_kprobe_get_name(kprobe, &tmp);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK, "Getting kprobe name.");
	ok(!strcmp(probe_name, tmp), "kprobe name are equal.");

	ok(lttng_event_rule_serialize(kprobe, &payload) == 0, "Serializing.");

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(
						&payload, 0, -1);

		ok(lttng_event_rule_create_from_payload(
				   &view, &kprobe_from_buffer) > 0,
				"Deserializing.");
	}

	ok(lttng_event_rule_is_equal(kprobe, kprobe_from_buffer),
			"serialized and from buffer are equal.");

	lttng_payload_reset(&payload);
	lttng_event_rule_destroy(kprobe);
	lttng_event_rule_destroy(kprobe_from_buffer);
}

static void test_event_rule_kprobe(void)
{
	struct lttng_kernel_probe_location *address_location = NULL;
	struct lttng_kernel_probe_location *symbol_location = NULL;

	address_location = lttng_kernel_probe_location_address_create(50);
	symbol_location = lttng_kernel_probe_location_symbol_create("une_bonne", 50);
	assert(address_location);
	assert(symbol_location);

	test_event_rule_kprobe_by_location(address_location);
	test_event_rule_kprobe_by_location(symbol_location);

	lttng_kernel_probe_location_destroy(address_location);
	lttng_kernel_probe_location_destroy(symbol_location);
}

int main(int argc, const char *argv[])
{
	plan_tests(NUM_TESTS);
	test_event_rule_tracepoint();
	test_event_rule_syscall();
	test_event_rule_uprobe();
	test_event_rule_kprobe();
	return exit_status();
}
