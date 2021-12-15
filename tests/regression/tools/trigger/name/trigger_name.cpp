/*
 * trigger_name.c
 *
 * Tests suite for anonymous, named, and automatic name triggers.
 *
 * Copyright (C) 2021 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <tap/tap.h>
#include <stdint.h>
#include <string.h>
#include <lttng/lttng.h>
#include <common/macros.hpp>

#define TEST_COUNT 70

enum unregistration_trigger_instance {
	UNREGISTRATION_TRIGGER_INSTANCE_USED_FOR_REGISTRATION,
	UNREGISTRATION_TRIGGER_INSTANCE_FROM_LISTING,
};

typedef void (*test_function)(enum unregistration_trigger_instance);

static
const char *get_trigger_name(const struct lttng_trigger *trigger)
{
	const char *trigger_name;
	enum lttng_trigger_status trigger_status;

	trigger_status = lttng_trigger_get_name(trigger, &trigger_name);
	switch (trigger_status) {
	case LTTNG_TRIGGER_STATUS_OK:
		break;
	case LTTNG_TRIGGER_STATUS_UNSET:
		trigger_name = "(anonymous)";
		break;
	default:
		trigger_name = "(failed to get name)";
		break;
	}

	return trigger_name;
}

static
const char *unregistration_trigger_instance_name(
		enum unregistration_trigger_instance unregistration_trigger)
{
	const char *name;

	switch (unregistration_trigger) {
	case UNREGISTRATION_TRIGGER_INSTANCE_FROM_LISTING:
		name = "from listing";
		break;
	case UNREGISTRATION_TRIGGER_INSTANCE_USED_FOR_REGISTRATION:
		name = "used for registration";
		break;
	default:
		abort();
	}

	return name;
}

/*
 * Returns a negative error code on error, else the number of unregistered
 * triggers.
 */
static
int unregister_all_triggers(void)
{
	int ret;
	enum lttng_error_code ret_code;
	enum lttng_trigger_status trigger_status;
	struct lttng_triggers *triggers = NULL;
	unsigned int trigger_count, i, unregistered_trigger_count = 0;

	ret_code = lttng_list_triggers(&triggers);
	if (ret_code != LTTNG_OK) {
		fail("Failed to list triggers");
		ret = -1;
		goto end;
	}

	trigger_status = lttng_triggers_get_count(triggers, &trigger_count);
	if (trigger_status != LTTNG_TRIGGER_STATUS_OK) {
		fail("Failed to get count of triggers returned by listing");
		ret = -1;
		goto end;
	}

	for (i = 0; i < trigger_count; i++) {
		const struct lttng_trigger *trigger;

		trigger = lttng_triggers_get_at_index(triggers, i);
		LTTNG_ASSERT(trigger);

		ret = lttng_unregister_trigger(trigger);
		if (ret) {
			const char *name;
			enum lttng_trigger_status get_name_status =
				lttng_trigger_get_name(trigger, &name);
			if (get_name_status == LTTNG_TRIGGER_STATUS_OK) {
				fail("Failed to unregister trigger: trigger name = '%s'", name);
			} else {
				fail("Failed to unregister trigger");
			}
			goto end;
		}

		unregistered_trigger_count++;
	}

	ret = (int) unregistered_trigger_count;

end:
	lttng_triggers_destroy(triggers);
	return ret;
}

static
int get_registered_triggers_count(void)
{
	int ret;
	enum lttng_error_code ret_code;
	enum lttng_trigger_status trigger_status;
	struct lttng_triggers *triggers = NULL;
	unsigned int trigger_count;

	ret_code = lttng_list_triggers(&triggers);
	if (ret_code != LTTNG_OK) {
		fail("Failed to list triggers");
		ret = -1;
		goto end;
	}

	trigger_status = lttng_triggers_get_count(triggers, &trigger_count);
	if (trigger_status != LTTNG_TRIGGER_STATUS_OK) {
		fail("Failed to get count of triggers returned by listing");
		ret = -1;
		goto end;
	}

	ret = (int) trigger_count;

end:
	lttng_triggers_destroy(triggers);
	return ret;
}

/*
 * Create a generic trigger. The specifics of the condition and action are not
 * important for the purposes of this test.
 */
static
struct lttng_trigger *create_trigger(uint64_t threshold)
{
	struct lttng_condition *condition = NULL;
	struct lttng_action *action = NULL;
	struct lttng_trigger *trigger = NULL;
	enum lttng_condition_status condition_status;
	const char * const session_name = "test session";

	condition = lttng_condition_session_consumed_size_create();
	if (!condition) {
		fail("Failed to create 'session consumed size' condition");
		goto end;
	}

	condition_status = lttng_condition_session_consumed_size_set_session_name(condition, session_name);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		fail("Failed to set session name on 'session consumed size' condition");
		goto end;
	}

	condition_status = lttng_condition_session_consumed_size_set_threshold(
			condition, threshold);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		fail("Failed to set threshold on 'session consumed size' condition");
		goto end;
	}

	action = lttng_action_notify_create();
	if (!action) {
		fail("Failed to create 'notify' action");
		goto end;
	}

	trigger = lttng_trigger_create(condition, action);
	if (!trigger) {
		fail("Failed to create trigger");
		goto end;
	}

end:
	lttng_condition_destroy(condition);
	lttng_action_destroy(action);
	return trigger;
}

static
void register_anonymous_trigger(
		enum unregistration_trigger_instance unregistration_trigger)
{
	int ret;
	struct lttng_trigger *trigger = create_trigger(0xbadc0ffee);
	enum lttng_trigger_status trigger_status;
	const char *trigger_name;
	struct lttng_triggers *triggers = NULL;
	unsigned int trigger_count, i;
	enum lttng_error_code ret_code;

	diag("Register an anonymous trigger (Unregistration performed with the trigger instance %s)",
			unregistration_trigger_instance_name(
					unregistration_trigger));

	if (!trigger) {
		fail("Failed to create trigger");
		goto end;
	}

	ret = lttng_register_trigger(trigger);
	ok(ret == 0, "Registered anonymous trigger");

	trigger_status = lttng_trigger_get_name(trigger, &trigger_name);
	ok(trigger_status == LTTNG_TRIGGER_STATUS_UNSET,
			"Anonymous trigger name remains unset after registration: trigger name = '%s'",
			get_trigger_name(trigger));

	ret_code = lttng_list_triggers(&triggers);
	if (ret_code != LTTNG_OK) {
		fail("Failed to list triggers");
		ret = -1;
		goto end;
	}

	trigger_status = lttng_triggers_get_count(triggers, &trigger_count);
	if (trigger_status != LTTNG_TRIGGER_STATUS_OK) {
		fail("Failed to get count of triggers returned by listing");
		ret = -1;
		goto end;
	}

	ok(trigger_count == 1, "Trigger listing returns 1 trigger");

	for (i = 0; i < trigger_count; i++) {
		const struct lttng_trigger *trigger_from_listing;

		trigger_from_listing = lttng_triggers_get_at_index(triggers, i);
		LTTNG_ASSERT(trigger_from_listing);

		trigger_status = lttng_trigger_get_name(trigger_from_listing, &trigger_name);
		ok(trigger_status == LTTNG_TRIGGER_STATUS_UNSET,
				"Anonymous trigger returned by listing has an unset name: trigger name = '%s'",
				get_trigger_name(trigger_from_listing));

		if (unregistration_trigger == UNREGISTRATION_TRIGGER_INSTANCE_FROM_LISTING) {
			ret = lttng_unregister_trigger(trigger_from_listing);
			ok(ret == 0, "Successfully unregistered anonymous trigger using the trigger instance returned by the listing");
		}
	}

	if (unregistration_trigger == UNREGISTRATION_TRIGGER_INSTANCE_USED_FOR_REGISTRATION) {
		ret = lttng_unregister_trigger(trigger);
		ok(ret == 0, "Successfully unregistered anonymous trigger using the trigger instance used on registration");
	}

end:
	lttng_triggers_destroy(triggers);
	lttng_trigger_destroy(trigger);
}

static
void register_named_trigger(
		enum unregistration_trigger_instance unregistration_trigger)
{
	int ret;
	struct lttng_trigger *trigger = create_trigger(0xbadc0ffee);
	enum lttng_trigger_status trigger_status;
	const char *returned_trigger_name;
	struct lttng_triggers *triggers = NULL;
	unsigned int trigger_count, i;
	enum lttng_error_code ret_code;
	const char * const trigger_name = "some name that is hopefully unique";

	diag("Register a named trigger (Unregistration performed with the trigger instance %s)",
			unregistration_trigger_instance_name(
					unregistration_trigger));

	if (!trigger) {
		fail("Failed to create trigger");
		goto end;
	}

	ret_code = lttng_register_trigger_with_name(trigger, trigger_name);
	ok(ret_code == LTTNG_OK, "Registered trigger with name: trigger name = '%s'",
			get_trigger_name(trigger));

	trigger_status = lttng_trigger_get_name(trigger, &returned_trigger_name);
	ok(trigger_status == LTTNG_TRIGGER_STATUS_OK,
			"Trigger name is set after registration: trigger name = '%s'",
			get_trigger_name(trigger));

	ok(!strcmp(get_trigger_name(trigger), trigger_name),
			"Name set on trigger after registration is correct");

	ret_code = lttng_list_triggers(&triggers);
	if (ret_code != LTTNG_OK) {
		fail("Failed to list triggers");
		ret = -1;
		goto end;
	}

	trigger_status = lttng_triggers_get_count(triggers, &trigger_count);
	if (trigger_status != LTTNG_TRIGGER_STATUS_OK) {
		fail("Failed to get count of triggers returned by listing");
		ret = -1;
		goto end;
	}

	ok(trigger_count == 1, "Trigger listing returns 1 trigger");

	for (i = 0; i < trigger_count; i++) {
		const struct lttng_trigger *trigger_from_listing;

		trigger_from_listing = lttng_triggers_get_at_index(triggers, i);
		LTTNG_ASSERT(trigger_from_listing);

		trigger_status = lttng_trigger_get_name(trigger_from_listing, &returned_trigger_name);
		ok(trigger_status == LTTNG_TRIGGER_STATUS_OK,
				"Trigger returned by listing has a name: trigger name = '%s'",
				get_trigger_name(trigger_from_listing));

		ok(!strcmp(get_trigger_name(trigger_from_listing),
				trigger_name),
				"Name set on trigger returned from listing is correct: name returned from listing = '%s', expected name = '%s'",
				get_trigger_name(trigger_from_listing),
				trigger_name);

		if (unregistration_trigger == UNREGISTRATION_TRIGGER_INSTANCE_FROM_LISTING) {
			ret = lttng_unregister_trigger(trigger_from_listing);
			ok(ret == 0, "Successfully unregistered named trigger using the trigger instance returned by the listing");
		}
	}

	if (unregistration_trigger == UNREGISTRATION_TRIGGER_INSTANCE_USED_FOR_REGISTRATION) {
		ret = lttng_unregister_trigger(trigger);
		ok(ret == 0, "Successfully unregistered named trigger using the trigger instance used on registration");
	}

end:
	lttng_triggers_destroy(triggers);
	lttng_trigger_destroy(trigger);
}

static
void register_automatic_name_trigger(
		enum unregistration_trigger_instance unregistration_trigger)
{
	int ret;
	struct lttng_trigger *trigger = create_trigger(0xbadc0ffee);
	enum lttng_trigger_status trigger_status;
	const char *returned_trigger_name;
	struct lttng_triggers *triggers = NULL;
	unsigned int trigger_count, i;
	enum lttng_error_code ret_code;

	diag("Register an automatic name trigger (Unregistration performed with the trigger instance %s)",
			unregistration_trigger_instance_name(
					unregistration_trigger));

	if (!trigger) {
		fail("Failed to create trigger");
		goto end;
	}

	ret_code = lttng_register_trigger_with_automatic_name(trigger);
	ok(ret_code == LTTNG_OK, "Registered trigger with automatic name");

	trigger_status = lttng_trigger_get_name(trigger, &returned_trigger_name);
	ok(trigger_status == LTTNG_TRIGGER_STATUS_OK,
			"Trigger name is set after registration: trigger name = '%s'",
			get_trigger_name(trigger));

	ok(returned_trigger_name && strlen(returned_trigger_name) > 0,
			"Automatic name set on trigger after registration longer is not an empty string");

	ret_code = lttng_list_triggers(&triggers);
	if (ret_code != LTTNG_OK) {
		fail("Failed to list triggers");
		ret = -1;
		goto end;
	}

	trigger_status = lttng_triggers_get_count(triggers, &trigger_count);
	if (trigger_status != LTTNG_TRIGGER_STATUS_OK) {
		fail("Failed to get count of triggers returned by listing");
		ret = -1;
		goto end;
	}

	ok(trigger_count == 1, "Trigger listing returns 1 trigger");

	for (i = 0; i < trigger_count; i++) {
		const struct lttng_trigger *trigger_from_listing;

		trigger_from_listing = lttng_triggers_get_at_index(triggers, i);
		LTTNG_ASSERT(trigger_from_listing);

		trigger_status = lttng_trigger_get_name(trigger_from_listing, &returned_trigger_name);
		ok(trigger_status == LTTNG_TRIGGER_STATUS_OK,
				"Trigger returned by listing has a name: trigger name = '%s'",
				get_trigger_name(trigger_from_listing));

		if (unregistration_trigger == UNREGISTRATION_TRIGGER_INSTANCE_FROM_LISTING) {
			ret = lttng_unregister_trigger(trigger_from_listing);
			ok(ret == 0, "Successfully unregistered automatic name trigger using the trigger instance returned by the listing");
		}
	}

	if (unregistration_trigger == UNREGISTRATION_TRIGGER_INSTANCE_USED_FOR_REGISTRATION) {
		ret = lttng_unregister_trigger(trigger);
		ok(ret == 0, "Successfully unregistered automatic trigger using the trigger instance used on registration");
	}

end:
	lttng_triggers_destroy(triggers);
	lttng_trigger_destroy(trigger);
}

static
void double_register_anonymous_trigger(
		enum unregistration_trigger_instance unregistration_trigger)
{
	int ret;
	struct lttng_trigger *trigger = create_trigger(0xbadc0ffee);
	struct lttng_triggers *triggers = NULL;

	diag("Register duplicate anonymous trigger (Unregistration performed with the trigger instance %s)",
			unregistration_trigger_instance_name(
					unregistration_trigger));

	if (!trigger) {
		fail("Failed to create trigger");
		goto end;
	}

	ret = lttng_register_trigger(trigger);
	ok(ret == 0, "Registered anonymous trigger");

	ret = lttng_register_trigger(trigger);
	ok(ret == -LTTNG_ERR_TRIGGER_EXISTS,
			"Registering identical anonymous trigger fails with `LTTNG_ERR_TRIGGER_EXISTS`");


	if (unregistration_trigger == UNREGISTRATION_TRIGGER_INSTANCE_USED_FOR_REGISTRATION) {
		ret = lttng_unregister_trigger(trigger);
		ok(ret == 0, "Successfully unregistered anonymous trigger using the trigger instance used on registration");
	} else {
		ok(get_registered_triggers_count() == 1,
				"Trigger listing returns 1 trigger");
		ok(unregister_all_triggers() == 1,
				"Successfully unregistered anonymous trigger using the trigger instance returned by the listing");
	}

end:
	lttng_triggers_destroy(triggers);
	lttng_trigger_destroy(trigger);
}

static
void double_register_named_trigger(
		enum unregistration_trigger_instance unregistration_trigger)
{
	int ret;
	struct lttng_trigger *trigger_a = create_trigger(0xbadc0ffee);
	struct lttng_trigger *trigger_b = create_trigger(0xbadc0ffee);
	struct lttng_triggers *triggers = NULL;
	const char * const trigger_name = "a unique trigger name";
	enum lttng_error_code ret_code;

	diag("Register duplicate named trigger (Unregistration performed with the trigger instance %s)",
			unregistration_trigger_instance_name(
					unregistration_trigger));

	if (!trigger_a || !trigger_b) {
		fail("Failed to create triggers");
		goto end;
	}

	ret_code = lttng_register_trigger_with_name(trigger_a, trigger_name);
	ok(ret_code == LTTNG_OK, "Registered named trigger");

	ret = lttng_register_trigger(trigger_a);
	ok(ret == -LTTNG_ERR_INVALID,
			"Registering a trigger instance already used for registration fails with `LTTNG_ERR_INVALID` (anonymous registration)");

	ret_code = lttng_register_trigger_with_name(trigger_a, trigger_name);
	ok(ret_code == LTTNG_ERR_INVALID,
			"Registering a trigger instance already used for registration fails with `LTTNG_ERR_INVALID` (register with name)");

	ret_code = lttng_register_trigger_with_automatic_name(trigger_a);
	ok(ret_code == LTTNG_ERR_INVALID,
			"Registering a trigger instance already used for registration fails with `LTTNG_ERR_INVALID` (register with automatic name)");

	ret_code = lttng_register_trigger_with_name(trigger_b, trigger_name);
	ok(ret_code == LTTNG_ERR_TRIGGER_EXISTS, "Registering trigger with an already used name fails with `LTTNG_ERR_TRIGGER_EXISTS`");

	if (unregistration_trigger == UNREGISTRATION_TRIGGER_INSTANCE_USED_FOR_REGISTRATION) {
		ret = lttng_unregister_trigger(trigger_a);
		ok(ret == 0, "Successfully unregistered named trigger using the trigger instance used on registration");
	} else {
		ok(get_registered_triggers_count() == 1,
				"Trigger listing returns 1 trigger");
		ok(unregister_all_triggers() == 1,
				"Successfully unregistered named trigger using the trigger instance returned by the listing");
	}

end:
	lttng_triggers_destroy(triggers);
	lttng_trigger_destroy(trigger_a);
	lttng_trigger_destroy(trigger_b);
}

static
void double_register_automatic_name_trigger(
		enum unregistration_trigger_instance unregistration_trigger)
{
	int ret;
	struct lttng_trigger *trigger_a = create_trigger(0xbadc0ffee);
	struct lttng_trigger *trigger_b = create_trigger(0xbadc0ffee);
	struct lttng_triggers *triggers = NULL;
	enum lttng_error_code ret_code;

	diag("Register duplicate automatic name trigger (Unregistration performed with the trigger instance %s)",
			unregistration_trigger_instance_name(
					unregistration_trigger));

	if (!trigger_a || !trigger_b) {
		fail("Failed to create triggers");
		goto end;
	}

	ret_code = lttng_register_trigger_with_automatic_name(trigger_a);
	ok(ret_code == LTTNG_OK, "Registered automatic name trigger: trigger name = '%s'", get_trigger_name(trigger_a));

	ret = lttng_register_trigger_with_automatic_name(trigger_b);
	ok(ret_code == LTTNG_OK, "Registering an identical trigger instance with an automatic name succeeds: trigger name = '%s'", get_trigger_name(trigger_b));

	ok(strcmp(get_trigger_name(trigger_a), get_trigger_name(trigger_b)),
			"Two identical triggers registered with an automatic name have different names");

	if (unregistration_trigger == UNREGISTRATION_TRIGGER_INSTANCE_USED_FOR_REGISTRATION) {
		ret = lttng_unregister_trigger(trigger_a);
		ok(ret == 0, "Successfully unregistered automatic trigger A using the trigger instance used on registration");

		ret = lttng_unregister_trigger(trigger_b);
		ok(ret == 0, "Successfully unregistered automatic trigger B using the trigger instance used on registration");
	} else {
		ok(get_registered_triggers_count() == 2,
				"Trigger listing returns 2 trigger");
		ok(unregister_all_triggers() == 2,
				"Successfully unregistered automatic name triggers using the trigger instance returned by the listing");
	}

end:
	lttng_triggers_destroy(triggers);
	lttng_trigger_destroy(trigger_a);
	lttng_trigger_destroy(trigger_b);
}

static
void register_multiple_anonymous_triggers(void)
{
	int ret;
	struct lttng_trigger *trigger_a = create_trigger(0xbadc0ffee);
	struct lttng_trigger *trigger_b = create_trigger(0xbadf00d);

	diag("Register two different anonymous triggers");

	if (!trigger_a || !trigger_b) {
		fail("Failed to create triggers");
		goto end;
	}

	ret = lttng_register_trigger(trigger_a);
	ok(ret == 0, "Registered first anonymous trigger");

	ret = lttng_register_trigger(trigger_b);
	ok(ret == 0, "Registered second anonymous trigger");

	ok(get_registered_triggers_count() == 2,
			"Trigger listing returns 2 trigger");
	ok(unregister_all_triggers() == 2,
			"Successfully unregistered two anonymous triggers");

end:
	lttng_trigger_destroy(trigger_a);
	lttng_trigger_destroy(trigger_b);
}

const test_function test_functions[] = {
	register_anonymous_trigger,
	register_named_trigger,
	register_automatic_name_trigger,
	double_register_anonymous_trigger,
	double_register_named_trigger,
	double_register_automatic_name_trigger,
};

int main(void)
{
	size_t i;

	plan_tests(TEST_COUNT);

	if (get_registered_triggers_count() != 0) {
		fail("Session daemon already has registered triggers, bailing out");
		goto end;
	}

	for (i = 0; i < ARRAY_SIZE(test_functions); i++) {
		const test_function fn = test_functions[i];

		fn(UNREGISTRATION_TRIGGER_INSTANCE_FROM_LISTING);
		if (get_registered_triggers_count() != 0) {
			fail("Previous test left registered triggers, bailing out");
			goto end;
		}
	}

	for (i = 0; i < ARRAY_SIZE(test_functions); i++) {
		const test_function fn = test_functions[i];

		fn(UNREGISTRATION_TRIGGER_INSTANCE_USED_FOR_REGISTRATION);
		if (get_registered_triggers_count() != 0) {
			fail("Previous test left registered triggers, bailing out");
			goto end;
		}
	}

	register_multiple_anonymous_triggers();
end:
	return exit_status();
}
