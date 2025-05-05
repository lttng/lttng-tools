/*
 * SPDX-FileCopyrightText: 2025 Philippe Proulx <pproulx@efficios.com>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <common/macros.hpp>
#include <common/make-unique-wrapper.hpp>
#include <common/string-utils/c-string-view.hpp>

#include <lttng/lttng.h>

#include <tap/tap.h>

namespace {

void check_event_name(lttng_kernel_probe_location& raw_loc, const char *const name)
{
	auto loc = lttng::make_unique_wrapper<lttng_kernel_probe_location,
					      lttng_kernel_probe_location_destroy>(&raw_loc);
	auto rule = lttng::make_unique_wrapper<lttng_event_rule, lttng_event_rule_destroy>(
		lttng_event_rule_kernel_kprobe_create(loc.get()));
	const char *actual_name;
	const auto ret = lttng_event_rule_kernel_kprobe_get_event_name(rule.get(), &actual_name);

	LTTNG_ASSERT(ret == LTTNG_EVENT_RULE_STATUS_OK);
	LTTNG_ASSERT(actual_name);

	if (!ok(lttng::c_string_view(actual_name) == name,
		"lttng_event_rule_kernel_kprobe_create - The event name `%s` is expected",
		name)) {
		diag("Expecting `%s`; got `%s`", name, actual_name);
	}
}

} /* namespace */

int main()
{
	plan_tests(3);
	check_event_name(*lttng_kernel_probe_location_symbol_create("meow_mix", 0), "meow_mix");
	check_event_name(*lttng_kernel_probe_location_symbol_create("meow_mix", 0xabcd1234),
			 "meow_mix+0xabcd1234");
	check_event_name(*lttng_kernel_probe_location_address_create(0xdeadbeef), "0xdeadbeef");
	return exit_status();
}
