/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_TRIGGER_INTERNAL_H
#define LTTNG_TRIGGER_INTERNAL_H

#include <common/credentials.h>
#include <common/dynamic-array.h>
#include <common/macros.h>
#include <common/optional.h>
#include <lttng/lttng.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <urcu/ref.h>

struct lttng_payload;
struct lttng_payload_view;

struct lttng_trigger {
	/* Reference counting is only exposed to internal users. */
	struct urcu_ref ref;

	struct lttng_condition *condition;
	struct lttng_action *action;
	char *name;
	/* For now only the uid portion of the credentials is used. */
	struct lttng_credentials creds;
	/*
	 * Internal use only.
	 * The unique token passed to the tracer to identify an event-rule
	 * notification.
	 */
	LTTNG_OPTIONAL(uint64_t) tracer_token;

	/*
	 * Is the trigger registered?
	 *
	 * This is necessary since a reference holder might be interested in the
	 * overall state of the trigger from the point of view of its owner.
	 *
	 * The main user is the action executor since we want to prevent the
	 * execution of actions related to a trigger that is unregistered.
	 *
	 * Not considered for `is_equal`.
	 */
	bool registered;

	/*
	 * The lock is used to protect against concurrent trigger execution and
	 * trigger removal.
	 */
	pthread_mutex_t lock;
};

struct lttng_triggers {
	struct lttng_dynamic_pointer_array array;
};

struct lttng_trigger_comm {
	/*
	 * Credentials, only the uid portion is used for now.
	 * Used as an override when desired by the root user.
	 */
	uint64_t uid;
	/*
	 * Length of the variable length payload (name, condition, and
	 * an action).
	 */
	uint32_t length;
	/* Includes '\0' terminator. */
	uint32_t name_length;
	/* A null-terminated name, a condition, and an action follow. */
	char payload[];
} LTTNG_PACKED;

struct lttng_triggers_comm {
	uint32_t count;
	uint32_t length;
	/* Count * lttng_trigger_comm structure */
	char payload[];
};

LTTNG_HIDDEN
ssize_t lttng_trigger_create_from_payload(struct lttng_payload_view *view,
		struct lttng_trigger **trigger);

LTTNG_HIDDEN
int lttng_trigger_serialize(const struct lttng_trigger *trigger,
		struct lttng_payload *payload);

LTTNG_HIDDEN
bool lttng_trigger_validate(const struct lttng_trigger *trigger);

LTTNG_HIDDEN
int lttng_trigger_assign_name(
		struct lttng_trigger *dst, const struct lttng_trigger *src);

LTTNG_HIDDEN
void lttng_trigger_set_tracer_token(
		struct lttng_trigger *trigger, uint64_t token);

LTTNG_HIDDEN
uint64_t lttng_trigger_get_tracer_token(const struct lttng_trigger *trigger);

LTTNG_HIDDEN
int lttng_trigger_generate_name(struct lttng_trigger *trigger,
		uint64_t unique_id);

LTTNG_HIDDEN
bool lttng_trigger_is_equal(
		const struct lttng_trigger *a, const struct lttng_trigger *b);

LTTNG_HIDDEN
void lttng_trigger_get(struct lttng_trigger *trigger);

LTTNG_HIDDEN
void lttng_trigger_put(struct lttng_trigger *trigger);

/*
 * Allocate a new set of triggers.
 * The returned object must be freed via lttng_triggers_destroy.
 */
LTTNG_HIDDEN
struct lttng_triggers *lttng_triggers_create(void);

/*
 * Return the a pointer to a mutable element at index "index" of an
 * lttng_triggers set.
 *
 * This differs from the public `lttng_triggers_get_at_index` in that
 * the returned pointer to a mutable trigger.
 *
 * The ownership of the trigger set element is NOT transfered.
 * The returned object can NOT be freed via lttng_trigger_destroy.
 */
LTTNG_HIDDEN
struct lttng_trigger *lttng_triggers_borrow_mutable_at_index(
		const struct lttng_triggers *triggers, unsigned int index);

/*
 * Add a trigger to the triggers set.
 *
 * A reference to the added trigger is acquired on behalf of the trigger set
 * on success.
 */
LTTNG_HIDDEN
int lttng_triggers_add(
		struct lttng_triggers *triggers, struct lttng_trigger *trigger);

/*
 * Serialize a trigger set to an lttng_payload object.
 * Return LTTNG_OK on success, negative lttng error code on error.
 */
LTTNG_HIDDEN
int lttng_triggers_serialize(const struct lttng_triggers *triggers,
		struct lttng_payload *payload);

LTTNG_HIDDEN
ssize_t lttng_triggers_create_from_payload(struct lttng_payload_view *view,
		struct lttng_triggers **triggers);

LTTNG_HIDDEN
const struct lttng_credentials *lttng_trigger_get_credentials(
		const struct lttng_trigger *trigger);

LTTNG_HIDDEN
void lttng_trigger_set_credentials(struct lttng_trigger *trigger,
		const struct lttng_credentials *creds);

/*
 * Return the type of any underlying domain restriction. If no particular
 * requirement is present, returns LTTNG_DOMAIN_NONE.
 */
LTTNG_HIDDEN
enum lttng_domain_type lttng_trigger_get_underlying_domain_type_restriction(
		const struct lttng_trigger *trigger);

/*
 * Generate any bytecode related to the trigger.
 * On success LTTNG_OK. On error, returns lttng_error code.
 */
LTTNG_HIDDEN
enum lttng_error_code lttng_trigger_generate_bytecode(
		struct lttng_trigger *trigger,
		const struct lttng_credentials *creds);

/*
 * Note that the trigger object is not locked by "copy" as it is const and
 * used with a number of 'const' triggers. If the trigger could be shared at
 * the moment of the copy, it is the caller's responsability to lock it for
 * the duration of the copy.
 */
LTTNG_HIDDEN
struct lttng_trigger *lttng_trigger_copy(const struct lttng_trigger *trigger);

/*
 * A given trigger needs a tracer notifier if
 *  it has an event-rule condition,
 *  AND
 *  it has one or more sessiond-execution action.
 */
LTTNG_HIDDEN
bool lttng_trigger_needs_tracer_notifier(const struct lttng_trigger *trigger);

LTTNG_HIDDEN
void lttng_trigger_set_as_registered(struct lttng_trigger *trigger);

LTTNG_HIDDEN
void lttng_trigger_set_as_unregistered(struct lttng_trigger *trigger);

/*
 * The trigger must be locked before calling lttng_trigger_is_registered.
 *
 * The lock is necessary since a trigger can be unregistered at any time.
 *
 * Manipulations requiring that the trigger be registered must always acquire
 * the trigger lock for the duration of the manipulation using
 * `lttng_trigger_lock` and `lttng_trigger_unlock`.
 */
LTTNG_HIDDEN
bool lttng_trigger_is_registered(struct lttng_trigger *trigger);

LTTNG_HIDDEN
void lttng_trigger_lock(struct lttng_trigger *trigger);

LTTNG_HIDDEN
void lttng_trigger_unlock(struct lttng_trigger *trigger);

LTTNG_HIDDEN
enum lttng_trigger_status lttng_trigger_add_error_results(
		const struct lttng_trigger *trigger,
		struct lttng_error_query_results *results);

LTTNG_HIDDEN
enum lttng_trigger_status lttng_trigger_add_action_error_query_results(
		struct lttng_trigger *trigger,
		struct lttng_error_query_results *results);

#endif /* LTTNG_TRIGGER_INTERNAL_H */
