/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_TRIGGER_INTERNAL_H
#define LTTNG_TRIGGER_INTERNAL_H

#include <common/credentials.hpp>
#include <common/dynamic-array.hpp>
#include <common/macros.hpp>
#include <common/optional.hpp>

#include <lttng/lttng.h>

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <urcu/ref.h>

struct lttng_payload;
struct lttng_payload_view;
struct mi_writer;
struct mi_lttng_error_query_callbacks;

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
	 * A "hidden" trigger is a trigger that is not externally listed.
	 * It is used to hide triggers that are used internally by the session
	 * daemon so that they can't be listed nor unregistered by external
	 * clients.
	 *
	 * This is a property that can only be set internally by the session
	 * daemon.
	 *
	 * The hidden property is preserved by copies.
	 *
	 * Note that notifications originating from an "hidden" trigger will not
	 * be sent to clients that are not within the session daemon's process.
	 */
	bool is_hidden;

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
	/* Hidden property. */
	uint8_t is_hidden;
	/* A null-terminated name, a condition, and an action follow. */
	char payload[];
} LTTNG_PACKED;

struct lttng_triggers_comm {
	uint32_t count;
	uint32_t length;
	/* Count * lttng_trigger_comm structure */
	char payload[];
};

ssize_t lttng_trigger_create_from_payload(struct lttng_payload_view *view,
					  struct lttng_trigger **trigger);

int lttng_trigger_serialize(const struct lttng_trigger *trigger, struct lttng_payload *payload);

bool lttng_trigger_validate(const struct lttng_trigger *trigger);

int lttng_trigger_assign_name(struct lttng_trigger *dst, const struct lttng_trigger *src);

void lttng_trigger_set_tracer_token(struct lttng_trigger *trigger, uint64_t token);

uint64_t lttng_trigger_get_tracer_token(const struct lttng_trigger *trigger);

int lttng_trigger_generate_name(struct lttng_trigger *trigger, uint64_t unique_id);

bool lttng_trigger_is_equal(const struct lttng_trigger *a, const struct lttng_trigger *b);

bool lttng_trigger_is_hidden(const struct lttng_trigger *trigger);

void lttng_trigger_set_hidden(struct lttng_trigger *trigger);

void lttng_trigger_get(struct lttng_trigger *trigger);

void lttng_trigger_put(struct lttng_trigger *trigger);

/*
 * Serialize a trigger to a mi_writer.
 * Return LTTNG_OK in success, other enum lttng_error_code on error.
 */
enum lttng_error_code
lttng_trigger_mi_serialize(const struct lttng_trigger *trigger,
			   struct mi_writer *writer,
			   const struct mi_lttng_error_query_callbacks *error_query_callbacks);

/*
 * Allocate a new set of triggers.
 * The returned object must be freed via lttng_triggers_destroy.
 */
struct lttng_triggers *lttng_triggers_create();

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
struct lttng_trigger *lttng_triggers_borrow_mutable_at_index(const struct lttng_triggers *triggers,
							     unsigned int index);

/*
 * Add a trigger to the triggers set.
 *
 * A reference to the added trigger is acquired on behalf of the trigger set
 * on success.
 */
int lttng_triggers_add(struct lttng_triggers *triggers, struct lttng_trigger *trigger);

/*
 * Remove all triggers marked as hidden from the provided trigger set.
 */
int lttng_triggers_remove_hidden_triggers(struct lttng_triggers *triggers);

/*
 * Serialize a trigger set to an lttng_payload object.
 * Return LTTNG_OK on success, negative lttng error code on error.
 */
int lttng_triggers_serialize(const struct lttng_triggers *triggers, struct lttng_payload *payload);

ssize_t lttng_triggers_create_from_payload(struct lttng_payload_view *view,
					   struct lttng_triggers **triggers);

/*
 * Serialize a trigger set to a mi_writer.
 * Return LTTNG_OK in success, other enum lttng_error_code on error.
 */
enum lttng_error_code
lttng_triggers_mi_serialize(const struct lttng_triggers *triggers,
			    struct mi_writer *writer,
			    const struct mi_lttng_error_query_callbacks *error_query_callbacks);

const struct lttng_credentials *lttng_trigger_get_credentials(const struct lttng_trigger *trigger);

void lttng_trigger_set_credentials(struct lttng_trigger *trigger,
				   const struct lttng_credentials *creds);

/*
 * Return the type of any underlying domain restriction. If no particular
 * requirement is present, returns LTTNG_DOMAIN_NONE.
 */
enum lttng_domain_type
lttng_trigger_get_underlying_domain_type_restriction(const struct lttng_trigger *trigger);

/*
 * Generate any bytecode related to the trigger.
 * On success LTTNG_OK. On error, returns lttng_error code.
 */
enum lttng_error_code lttng_trigger_generate_bytecode(struct lttng_trigger *trigger,
						      const struct lttng_credentials *creds);

/*
 * Note that the trigger object is not locked by "copy" as it is const and
 * used with a number of 'const' triggers. If the trigger could be shared at
 * the moment of the copy, it is the caller's responsability to lock it for
 * the duration of the copy.
 */
struct lttng_trigger *lttng_trigger_copy(const struct lttng_trigger *trigger);

/*
 * A given trigger needs a tracer notifier if
 *  it has an event-rule condition,
 *  AND
 *  it has one or more sessiond-execution action.
 */
bool lttng_trigger_needs_tracer_notifier(const struct lttng_trigger *trigger);

void lttng_trigger_set_as_registered(struct lttng_trigger *trigger);

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
bool lttng_trigger_is_registered(struct lttng_trigger *trigger);

void lttng_trigger_lock(struct lttng_trigger *trigger);

void lttng_trigger_unlock(struct lttng_trigger *trigger);

enum lttng_trigger_status
lttng_trigger_add_error_results(const struct lttng_trigger *trigger,
				struct lttng_error_query_results *results);

enum lttng_trigger_status
lttng_trigger_condition_add_error_results(const struct lttng_trigger *trigger,
					  struct lttng_error_query_results *results);

enum lttng_trigger_status
lttng_trigger_add_action_error_query_results(struct lttng_trigger *trigger,
					     struct lttng_error_query_results *results);

/*
 * Set the trigger name.
 *
 * A name is optional.
 * A name will be assigned on trigger registration if no name is set.
 *
 * The name is copied.
 *
 * Return LTTNG_TRIGGER_STATUS_OK on success, LTTNG_TRIGGER_STATUS_INVALID
 * if invalid parameters are passed.
 */
enum lttng_trigger_status lttng_trigger_set_name(struct lttng_trigger *trigger, const char *name);

#endif /* LTTNG_TRIGGER_INTERNAL_H */
