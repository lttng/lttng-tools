/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <assert.h>
#include <common/credentials.h>
#include <common/dynamic-array.h>
#include <common/error.h>
#include <common/optional.h>
#include <common/payload-view.h>
#include <common/payload.h>
#include <inttypes.h>
#include <lttng/action/action-internal.h>
#include <lttng/condition/buffer-usage.h>
#include <lttng/condition/condition-internal.h>
#include <lttng/condition/event-rule-matches-internal.h>
#include <lttng/condition/event-rule-matches.h>
#include <lttng/domain.h>
#include <lttng/event-expr-internal.h>
#include <lttng/event-rule/event-rule-internal.h>
#include <lttng/trigger/trigger-internal.h>
#include <pthread.h>

LTTNG_HIDDEN
bool lttng_trigger_validate(const struct lttng_trigger *trigger)
{
	bool valid;

	if (!trigger) {
		valid = false;
		goto end;
	}

	if (!trigger->creds.uid.is_set) {
		valid = false;
		goto end;
	}

	valid = lttng_condition_validate(trigger->condition) &&
			lttng_action_validate(trigger->action);
end:
	return valid;
}

struct lttng_trigger *lttng_trigger_create(
		struct lttng_condition *condition,
		struct lttng_action *action)
{
	struct lttng_trigger *trigger = NULL;

	if (!condition || !action) {
		goto end;
	}

	trigger = zmalloc(sizeof(struct lttng_trigger));
	if (!trigger) {
		goto end;
	}

	urcu_ref_init(&trigger->ref);

	lttng_condition_get(condition);
	trigger->condition = condition;

	lttng_action_get(action);
	trigger->action = action;

	pthread_mutex_init(&trigger->lock, NULL);
	trigger->registered = false;

end:
	return trigger;
}

/*
 * Note: the lack of reference counting 'get' on the condition object is normal.
 * This API was exposed as such in 2.11. The client is not expected to call
 * lttng_condition_destroy on the returned object.
 */
struct lttng_condition *lttng_trigger_get_condition(
		struct lttng_trigger *trigger)
{
	return trigger ? trigger->condition : NULL;
}

const struct lttng_condition *lttng_trigger_get_const_condition(
		const struct lttng_trigger *trigger)
{
	return trigger ? trigger->condition : NULL;
}

/*
 * Note: the lack of reference counting 'get' on the action object is normal.
 * This API was exposed as such in 2.11. The client is not expected to call
 * lttng_action_destroy on the returned object.
 */
struct lttng_action *lttng_trigger_get_action(
		struct lttng_trigger *trigger)
{
	return trigger ? trigger->action : NULL;
}

const struct lttng_action *lttng_trigger_get_const_action(
		const struct lttng_trigger *trigger)
{
	return trigger ? trigger->action : NULL;
}

static void trigger_destroy_ref(struct urcu_ref *ref)
{
	struct lttng_trigger *trigger =
			container_of(ref, struct lttng_trigger, ref);
	struct lttng_action *action = lttng_trigger_get_action(trigger);
	struct lttng_condition *condition =
			lttng_trigger_get_condition(trigger);

	assert(action);
	assert(condition);

	/* Release ownership. */
	lttng_action_put(action);
	lttng_condition_put(condition);

	pthread_mutex_destroy(&trigger->lock);

	free(trigger->name);
	free(trigger);
}

void lttng_trigger_destroy(struct lttng_trigger *trigger)
{
	lttng_trigger_put(trigger);
}

LTTNG_HIDDEN
ssize_t lttng_trigger_create_from_payload(
		struct lttng_payload_view *src_view,
		struct lttng_trigger **_trigger)
{
	ssize_t ret, offset = 0, condition_size, action_size, name_size = 0;
	struct lttng_condition *condition = NULL;
	struct lttng_action *action = NULL;
	const struct lttng_trigger_comm *trigger_comm;
	const char *name = NULL;
	struct lttng_credentials creds = {
		.uid = LTTNG_OPTIONAL_INIT_UNSET,
		.gid = LTTNG_OPTIONAL_INIT_UNSET,
	};
	struct lttng_trigger *trigger = NULL;
	const struct lttng_payload_view trigger_comm_view =
			lttng_payload_view_from_view(
					src_view, 0, sizeof(*trigger_comm));

	if (!src_view || !_trigger) {
		ret = -1;
		goto end;
	}

	if (!lttng_payload_view_is_valid(&trigger_comm_view)) {
		/* Payload not large enough to contain the header. */
		ret = -1;
		goto end;
	}

	/* lttng_trigger_comm header */
	trigger_comm = (typeof(trigger_comm)) trigger_comm_view.buffer.data;

	/* Set the trigger's creds. */
	if (trigger_comm->uid > (uint64_t) ((uid_t) -1)) {
		/* UID out of range for this platform. */
		ret = -1;
		goto end;
	}

	LTTNG_OPTIONAL_SET(&creds.uid, trigger_comm->uid);

	offset += sizeof(*trigger_comm);

	if (trigger_comm->name_length != 0) {
		/* Name. */
		const struct lttng_payload_view name_view =
				lttng_payload_view_from_view(
						src_view, offset,
						trigger_comm->name_length);

		if (!lttng_payload_view_is_valid(&name_view)) {
			ret = -1;
			goto end;
		}

		name = name_view.buffer.data;
		if (!lttng_buffer_view_contains_string(&name_view.buffer, name,
				    trigger_comm->name_length)) {
			ret = -1;
			goto end;
		}

		offset += trigger_comm->name_length;
		name_size = trigger_comm->name_length;
	}

	{
		/* struct lttng_condition */
		struct lttng_payload_view condition_view =
				lttng_payload_view_from_view(
						src_view, offset, -1);

		condition_size = lttng_condition_create_from_payload(&condition_view,
				&condition);
	}

	if (condition_size < 0) {
		ret = condition_size;
		goto end;
	}

	offset += condition_size;
	{
		/* struct lttng_action */
		struct lttng_payload_view action_view =
				lttng_payload_view_from_view(
					src_view, offset, -1);

		action_size = lttng_action_create_from_payload(&action_view, &action);
	}

	if (action_size < 0) {
		ret = action_size;
		goto end;
	}
	offset += action_size;

	/* Unexpected size of inner-elements; the buffer is corrupted. */
	if ((ssize_t) trigger_comm->length != condition_size + action_size + name_size) {
		ret = -1;
		goto error;
	}

	trigger = lttng_trigger_create(condition, action);
	if (!trigger) {
		ret = -1;
		goto error;
	}

	lttng_trigger_set_credentials(trigger, &creds);

	/*
	 * The trigger object owns references to the action and condition
	 * objects.
	 */
	lttng_condition_put(condition);
	condition = NULL;

	lttng_action_put(action);
	action = NULL;

	if (name) {
		const enum lttng_trigger_status status =
				lttng_trigger_set_name(trigger, name);

		if (status != LTTNG_TRIGGER_STATUS_OK) {
			ret = -1;
			goto end;
		}
	}

	ret = offset;

error:
	lttng_condition_put(condition);
	lttng_action_put(action);
end:
	if (ret >= 0) {
		*_trigger = trigger;
	} else {
		lttng_trigger_put(trigger);
	}

	return ret;
}

/*
 * Both elements are stored contiguously, see their "*_comm" structure
 * for the detailed format.
 */
LTTNG_HIDDEN
int lttng_trigger_serialize(const struct lttng_trigger *trigger,
		struct lttng_payload *payload)
{
	int ret;
	size_t header_offset, size_before_payload, size_name;
	struct lttng_trigger_comm trigger_comm = {};
	struct lttng_trigger_comm *header;
	const struct lttng_credentials *creds = NULL;

	creds = lttng_trigger_get_credentials(trigger);
	assert(creds);

	trigger_comm.uid = LTTNG_OPTIONAL_GET(creds->uid);

	if (trigger->name != NULL) {
		size_name = strlen(trigger->name) + 1;
	} else {
		size_name = 0;
	}

	trigger_comm.name_length = size_name;

	header_offset = payload->buffer.size;
	ret = lttng_dynamic_buffer_append(&payload->buffer, &trigger_comm,
			sizeof(trigger_comm));
	if (ret) {
		goto end;
	}

	size_before_payload = payload->buffer.size;

	/* Trigger name. */
	ret = lttng_dynamic_buffer_append(
			&payload->buffer, trigger->name, size_name);
	if (ret) {
		goto end;
	}

	ret = lttng_condition_serialize(trigger->condition, payload);
	if (ret) {
		goto end;
	}

	ret = lttng_action_serialize(trigger->action, payload);
	if (ret) {
		goto end;
	}

	/* Update payload size. */
	header = (typeof(header)) (payload->buffer.data + header_offset);
	header->length = payload->buffer.size - size_before_payload;
end:
	return ret;
}

LTTNG_HIDDEN
bool lttng_trigger_is_equal(
		const struct lttng_trigger *a, const struct lttng_trigger *b)
{
	if (strcmp(a->name, b->name) != 0) {
		return false;
	}

	if (!lttng_condition_is_equal(a->condition, b->condition)) {
		return false;
	}

	if (!lttng_action_is_equal(a->action, b->action)) {
		return false;
	}

	if (!lttng_credentials_is_equal(lttng_trigger_get_credentials(a),
			lttng_trigger_get_credentials(b))) {
		return false;
	}

	return true;
}

enum lttng_trigger_status lttng_trigger_set_name(struct lttng_trigger *trigger,
		const char* name)
{
	char *name_copy = NULL;
	enum lttng_trigger_status status = LTTNG_TRIGGER_STATUS_OK;

	if (!trigger || !name ||
			strlen(name) == 0) {
		status = LTTNG_TRIGGER_STATUS_INVALID;
		goto end;
	}

	name_copy = strdup(name);
	if (!name_copy) {
		status = LTTNG_TRIGGER_STATUS_ERROR;
		goto end;
	}

	free(trigger->name);

	trigger->name = name_copy;
	name_copy = NULL;
end:
	return status;
}

enum lttng_trigger_status lttng_trigger_get_name(
		const struct lttng_trigger *trigger, const char **name)
{
	enum lttng_trigger_status status = LTTNG_TRIGGER_STATUS_OK;

	if (!trigger || !name) {
		status = LTTNG_TRIGGER_STATUS_INVALID;
		goto end;
	}

	if (!trigger->name) {
		status = LTTNG_TRIGGER_STATUS_UNSET;
	}

	*name = trigger->name;
end:
	return status;
}

LTTNG_HIDDEN
int lttng_trigger_assign_name(struct lttng_trigger *dst,
		const struct lttng_trigger *src)
{
	int ret = 0;
	enum lttng_trigger_status status;

	status = lttng_trigger_set_name(dst, src->name);
	if (status != LTTNG_TRIGGER_STATUS_OK) {
		ret = -1;
		ERR("Failed to set name for trigger");
		goto end;
	}
end:
	return ret;
}

LTTNG_HIDDEN
void lttng_trigger_set_tracer_token(struct lttng_trigger *trigger,
		uint64_t token)
{
	assert(trigger);
	LTTNG_OPTIONAL_SET(&trigger->tracer_token, token);
}

LTTNG_HIDDEN
uint64_t lttng_trigger_get_tracer_token(const struct lttng_trigger *trigger)
{
	assert(trigger);

	return LTTNG_OPTIONAL_GET(trigger->tracer_token);
}

LTTNG_HIDDEN
int lttng_trigger_generate_name(struct lttng_trigger *trigger,
		uint64_t unique_id)
{
	int ret = 0;
	char *generated_name = NULL;

	ret = asprintf(&generated_name, "T%" PRIu64 "", unique_id);
	if (ret < 0) {
		ERR("Failed to generate trigger name");
		ret = -1;
		goto end;
	}

	ret = 0;
	free(trigger->name);
	trigger->name = generated_name;
end:
	return ret;
}

LTTNG_HIDDEN
void lttng_trigger_get(struct lttng_trigger *trigger)
{
	urcu_ref_get(&trigger->ref);
}

LTTNG_HIDDEN
void lttng_trigger_put(struct lttng_trigger *trigger)
{
	if (!trigger) {
		return;
	}

	urcu_ref_put(&trigger->ref , trigger_destroy_ref);
}

static void delete_trigger_array_element(void *ptr)
{
	struct lttng_trigger *trigger = ptr;

	lttng_trigger_put(trigger);
}

LTTNG_HIDDEN
struct lttng_triggers *lttng_triggers_create(void)
{
	struct lttng_triggers *triggers = NULL;

	triggers = zmalloc(sizeof(*triggers));
	if (!triggers) {
		goto end;
	}

	lttng_dynamic_pointer_array_init(&triggers->array, delete_trigger_array_element);

end:
	return triggers;
}

LTTNG_HIDDEN
struct lttng_trigger *lttng_triggers_borrow_mutable_at_index(
		const struct lttng_triggers *triggers, unsigned int index)
{
	struct lttng_trigger *trigger = NULL;

	assert(triggers);
	if (index >= lttng_dynamic_pointer_array_get_count(&triggers->array)) {
		goto end;
	}

	trigger = (struct lttng_trigger *)
			lttng_dynamic_pointer_array_get_pointer(
					&triggers->array, index);
end:
	return trigger;
}

LTTNG_HIDDEN
int lttng_triggers_add(
		struct lttng_triggers *triggers, struct lttng_trigger *trigger)
{
	int ret;

	assert(triggers);
	assert(trigger);

	lttng_trigger_get(trigger);

	ret = lttng_dynamic_pointer_array_add_pointer(&triggers->array, trigger);
	if (ret) {
		lttng_trigger_put(trigger);
	}

	return ret;
}

const struct lttng_trigger *lttng_triggers_get_at_index(
		const struct lttng_triggers *triggers, unsigned int index)
{
	return lttng_triggers_borrow_mutable_at_index(triggers, index);
}

enum lttng_trigger_status lttng_triggers_get_count(const struct lttng_triggers *triggers, unsigned int *count)
{
	enum lttng_trigger_status status = LTTNG_TRIGGER_STATUS_OK;

	if (!triggers || !count) {
		status = LTTNG_TRIGGER_STATUS_INVALID;
		goto end;
	}

	*count = lttng_dynamic_pointer_array_get_count(&triggers->array);
end:
	return status;
}

void lttng_triggers_destroy(struct lttng_triggers *triggers)
{
	if (!triggers) {
		return;
	}

	lttng_dynamic_pointer_array_reset(&triggers->array);
	free(triggers);
}

int lttng_triggers_serialize(const struct lttng_triggers *triggers,
		struct lttng_payload *payload)
{
	int ret;
	unsigned int i, count;
	size_t size_before_payload;
	struct lttng_triggers_comm triggers_comm = {};
	struct lttng_triggers_comm *header;
	enum lttng_trigger_status status;
	const size_t header_offset = payload->buffer.size;

	status = lttng_triggers_get_count(triggers, &count);
	if (status != LTTNG_TRIGGER_STATUS_OK) {
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	triggers_comm.count = count;

	/* Placeholder header; updated at the end. */
	ret = lttng_dynamic_buffer_append(&payload->buffer, &triggers_comm,
			sizeof(triggers_comm));
	if (ret) {
		goto end;
	}

	size_before_payload = payload->buffer.size;

	for (i = 0; i < count; i++) {
		const struct lttng_trigger *trigger =
				lttng_triggers_get_at_index(triggers, i);

		assert(trigger);

		ret = lttng_trigger_serialize(trigger, payload);
		if (ret) {
			goto end;
		}
	}

	/* Update payload size. */
	header = (struct lttng_triggers_comm *) ((char *) payload->buffer.data + header_offset);
	header->length = payload->buffer.size - size_before_payload;
end:
	return ret;
}

LTTNG_HIDDEN
ssize_t lttng_triggers_create_from_payload(
		struct lttng_payload_view *src_view,
		struct lttng_triggers **triggers)
{
	ssize_t ret, offset = 0, triggers_size = 0;
	unsigned int i;
	const struct lttng_triggers_comm *triggers_comm;
	struct lttng_triggers *local_triggers = NULL;

	if (!src_view || !triggers) {
		ret = -1;
		goto error;
	}

	/* lttng_trigger_comms header */
	triggers_comm = (const struct lttng_triggers_comm *) src_view->buffer.data;
	offset += sizeof(*triggers_comm);

	local_triggers = lttng_triggers_create();
	if (!local_triggers) {
		ret = -1;
		goto error;
	}

	for (i = 0; i < triggers_comm->count; i++) {
		struct lttng_trigger *trigger = NULL;
		struct lttng_payload_view trigger_view =
				lttng_payload_view_from_view(src_view, offset, -1);
		ssize_t trigger_size;

		trigger_size = lttng_trigger_create_from_payload(
				&trigger_view, &trigger);
		if (trigger_size < 0) {
			ret = trigger_size;
			goto error;
		}

		/* Transfer ownership of the trigger to the collection. */
		ret = lttng_triggers_add(local_triggers, trigger);
		lttng_trigger_put(trigger);
		if (ret < 0) {
			ret = -1;
			goto error;
		}

		offset += trigger_size;
		triggers_size += trigger_size;
	}

	/* Unexpected size of inner-elements; the buffer is corrupted. */
	if ((ssize_t) triggers_comm->length != triggers_size) {
		ret = -1;
		goto error;
	}

	/* Pass ownership to caller. */
	*triggers = local_triggers;
	local_triggers = NULL;

	ret = offset;
error:

	lttng_triggers_destroy(local_triggers);
	return ret;
}

LTTNG_HIDDEN
const struct lttng_credentials *lttng_trigger_get_credentials(
		const struct lttng_trigger *trigger)
{
	return &trigger->creds;
}

LTTNG_HIDDEN
void lttng_trigger_set_credentials(struct lttng_trigger *trigger,
		const struct lttng_credentials *creds)
{
	assert(creds);
	trigger->creds = *creds;
}

enum lttng_trigger_status lttng_trigger_set_owner_uid(
		struct lttng_trigger *trigger, uid_t uid)
{
	enum lttng_trigger_status ret = LTTNG_TRIGGER_STATUS_OK;
	const uid_t euid = geteuid();
	const struct lttng_credentials creds = {
		.uid = LTTNG_OPTIONAL_INIT_VALUE(uid),
		.gid = LTTNG_OPTIONAL_INIT_UNSET,
	};

	if (!trigger) {
		ret = LTTNG_TRIGGER_STATUS_INVALID;
		goto end;
	}

	/* Client-side validation only to report a clearer error. */
	if (euid != 0 && euid != uid) {
		ret = LTTNG_TRIGGER_STATUS_PERMISSION_DENIED;
		goto end;
	}

	lttng_trigger_set_credentials(trigger, &creds);

end:
	return ret;
}

enum lttng_trigger_status lttng_trigger_get_owner_uid(
		const struct lttng_trigger *trigger, uid_t *uid)
{
	enum lttng_trigger_status ret = LTTNG_TRIGGER_STATUS_OK;
	const struct lttng_credentials *creds = NULL;

	if (!trigger || !uid ) {
		ret = LTTNG_TRIGGER_STATUS_INVALID;
		goto end;
	}

	if (!trigger->creds.uid.is_set ) {
		ret = LTTNG_TRIGGER_STATUS_UNSET;
		goto end;
	}

	creds = lttng_trigger_get_credentials(trigger);
	*uid = lttng_credentials_get_uid(creds);

end:
	return ret;
}

LTTNG_HIDDEN
enum lttng_domain_type lttng_trigger_get_underlying_domain_type_restriction(
		const struct lttng_trigger *trigger)
{
	enum lttng_domain_type type = LTTNG_DOMAIN_NONE;
	const struct lttng_event_rule *event_rule;
	enum lttng_condition_status c_status;
	enum lttng_condition_type c_type;

	assert(trigger);
	assert(trigger->condition);

	c_type = lttng_condition_get_type(trigger->condition);
	assert (c_type != LTTNG_CONDITION_TYPE_UNKNOWN);

	switch (c_type) {
	case LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE:
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING:
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED:
		/* Apply to any domain. */
		type = LTTNG_DOMAIN_NONE;
		break;
	case LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES:
		/* Return the domain of the event rule. */
		c_status = lttng_condition_event_rule_matches_get_rule(
				trigger->condition, &event_rule);
		assert(c_status == LTTNG_CONDITION_STATUS_OK);
		type = lttng_event_rule_get_domain_type(event_rule);
		break;
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
		/* Return the domain of the channel being monitored. */
		c_status = lttng_condition_buffer_usage_get_domain_type(
				trigger->condition, &type);
		assert(c_status == LTTNG_CONDITION_STATUS_OK);
		break;
	default:
		abort();
	}

	return type;
}

/*
 * Generate bytecode related to the trigger.
 * On success LTTNG_OK. On error, returns lttng_error code.
 */
LTTNG_HIDDEN
enum lttng_error_code lttng_trigger_generate_bytecode(
		struct lttng_trigger *trigger,
		const struct lttng_credentials *creds)
{
	enum lttng_error_code ret;
	struct lttng_condition *condition = NULL;

	condition = lttng_trigger_get_condition(trigger);
	if (!condition) {
		ret = LTTNG_ERR_INVALID_TRIGGER;
		goto end;
	}

	switch (lttng_condition_get_type(condition)) {
	case LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES:
	{
		struct lttng_event_rule *event_rule;
		const enum lttng_condition_status condition_status =
				lttng_condition_event_rule_matches_borrow_rule_mutable(
						condition, &event_rule);

		assert(condition_status == LTTNG_CONDITION_STATUS_OK);

		/* Generate the filter bytecode. */
		ret = lttng_event_rule_generate_filter_bytecode(
				event_rule, creds);
		if (ret != LTTNG_OK) {
			goto end;
		}

		/* Generate the capture bytecode. */
		ret = lttng_condition_event_rule_matches_generate_capture_descriptor_bytecode(
				condition);
		if (ret != LTTNG_OK) {
			goto end;
		}

		ret = LTTNG_OK;
		break;
	}
	default:
		ret = LTTNG_OK;
		break;
	}
end:
	return ret;
}

LTTNG_HIDDEN
struct lttng_trigger *lttng_trigger_copy(const struct lttng_trigger *trigger)
{
	int ret;
	struct lttng_payload copy_buffer;
	struct lttng_condition *condition_copy = NULL;
	struct lttng_action *action_copy = NULL;
	struct lttng_trigger *copy = NULL;
	enum lttng_trigger_status trigger_status;
	const char *trigger_name;
	uid_t trigger_owner_uid;

	lttng_payload_init(&copy_buffer);

	ret = lttng_condition_serialize(trigger->condition, &copy_buffer);
	if (ret < 0) {
		goto end;
	}

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(
						&copy_buffer, 0, -1);

		ret = lttng_condition_create_from_payload(
				&view, &condition_copy);
		if (ret < 0) {
			goto end;
		}
	}

	lttng_payload_clear(&copy_buffer);

	ret = lttng_action_serialize(trigger->action, &copy_buffer);
	if (ret < 0) {
		goto end;
	}

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(
						&copy_buffer, 0, -1);

		ret = lttng_action_create_from_payload(
				&view, &action_copy);
		if (ret < 0) {
			goto end;
		}
	}

	copy = lttng_trigger_create(condition_copy, action_copy);
	if (!copy) {
		ERR("Failed to allocate trigger during trigger copy");
		goto end;
	}

	trigger_status = lttng_trigger_get_name(trigger, &trigger_name);
	switch (trigger_status) {
	case LTTNG_TRIGGER_STATUS_OK:
		trigger_status = lttng_trigger_set_name(copy, trigger_name);
		if (trigger_status != LTTNG_TRIGGER_STATUS_OK) {
			ERR("Failed to set name of new trigger during copy");
			goto error_cleanup_trigger;
		}
		break;
	case LTTNG_TRIGGER_STATUS_UNSET:
		break;
	default:
		ERR("Failed to get name of original trigger during copy");
		goto error_cleanup_trigger;
	}

	trigger_status = lttng_trigger_get_owner_uid(
			trigger, &trigger_owner_uid);
	switch (trigger_status) {
	case LTTNG_TRIGGER_STATUS_OK:
		LTTNG_OPTIONAL_SET(&copy->creds.uid, trigger_owner_uid);
		break;
	case LTTNG_TRIGGER_STATUS_UNSET:
		break;
	default:
		ERR("Failed to get owner uid of original trigger during copy");
		goto error_cleanup_trigger;
	}

	copy->tracer_token = trigger->tracer_token;
	copy->registered = trigger->registered;
	goto end;

error_cleanup_trigger:
	lttng_trigger_destroy(copy);
	copy = NULL;
end:
	lttng_condition_put(condition_copy);
	lttng_action_put(action_copy);
	lttng_payload_reset(&copy_buffer);
	return copy;
}

LTTNG_HIDDEN
bool lttng_trigger_needs_tracer_notifier(const struct lttng_trigger *trigger)
{
	bool needs_tracer_notifier = false;
	const struct lttng_condition *condition =
			lttng_trigger_get_const_condition(trigger);

	switch (lttng_condition_get_type(condition)) {
	case LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES:
		needs_tracer_notifier = true;
		goto end;
	case LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE:
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING:
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED:
		goto end;
	case LTTNG_CONDITION_TYPE_UNKNOWN:
	default:
		abort();
	}
end:
	return needs_tracer_notifier;
}

LTTNG_HIDDEN
void lttng_trigger_set_as_registered(struct lttng_trigger *trigger)
{
	pthread_mutex_lock(&trigger->lock);
	trigger->registered = true;
	pthread_mutex_unlock(&trigger->lock);
}

LTTNG_HIDDEN
void lttng_trigger_set_as_unregistered(struct lttng_trigger *trigger)
{
	pthread_mutex_lock(&trigger->lock);
	trigger->registered = false;
	pthread_mutex_unlock(&trigger->lock);
}

/*
 * The trigger must be locked before calling lttng_trigger_registered.
 * The lock is necessary since a trigger can be unregistered at anytime.
 * Manipulations requiring that the trigger be registered must always acquire
 * the trigger lock for the duration of the manipulation using
 * `lttng_trigger_lock` and `lttng_trigger_unlock`.
 */
LTTNG_HIDDEN
bool lttng_trigger_is_registered(struct lttng_trigger *trigger)
{
	ASSERT_LOCKED(trigger->lock);
	return trigger->registered;
}

LTTNG_HIDDEN
void lttng_trigger_lock(struct lttng_trigger *trigger)
{
	pthread_mutex_lock(&trigger->lock);
}

LTTNG_HIDDEN
void lttng_trigger_unlock(struct lttng_trigger *trigger)
{
	pthread_mutex_unlock(&trigger->lock);
}
