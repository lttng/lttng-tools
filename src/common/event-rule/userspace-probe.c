/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <assert.h>
#include <common/credentials.h>
#include <common/error.h>
#include <common/macros.h>
#include <common/payload.h>
#include <common/payload-view.h>
#include <common/runas.h>
#include <common/hashtable/hashtable.h>
#include <common/hashtable/utils.h>
#include <lttng/event-rule/event-rule-internal.h>
#include <lttng/event-rule/userspace-probe-internal.h>
#include <lttng/userspace-probe-internal.h>

#define IS_UPROBE_EVENT_RULE(rule) \
	(lttng_event_rule_get_type(rule) == LTTNG_EVENT_RULE_TYPE_USERSPACE_PROBE)

static void lttng_event_rule_userspace_probe_destroy(struct lttng_event_rule *rule)
{
	struct lttng_event_rule_userspace_probe *uprobe;

	uprobe = container_of(rule, struct lttng_event_rule_userspace_probe, parent);

	lttng_userspace_probe_location_destroy(uprobe->location);
	free(uprobe->name);
	free(uprobe);
}

static bool lttng_event_rule_userspace_probe_validate(
		const struct lttng_event_rule *rule)
{
	bool valid = false;
	struct lttng_event_rule_userspace_probe *uprobe;

	if (!rule) {
		goto end;
	}

	uprobe = container_of(rule, struct lttng_event_rule_userspace_probe, parent);

	/* Required field. */
	if (!uprobe->name) {
		ERR("Invalid uprobe event rule: a pattern must be set.");
		goto end;
	}

	if (!uprobe->location) {
		ERR("Invalid uprobe event rule: a location must be set.");
		goto end;
	}

	valid = true;
end:
	return valid;
}

static int lttng_event_rule_userspace_probe_serialize(
		const struct lttng_event_rule *rule,
		struct lttng_payload *payload)
{
	int ret;
	size_t name_len, header_offset, size_before_probe;
	struct lttng_event_rule_userspace_probe *uprobe;
	struct lttng_event_rule_userspace_probe_comm uprobe_comm = {};
	struct lttng_event_rule_userspace_probe_comm *header;

	if (!rule || !IS_UPROBE_EVENT_RULE(rule)) {
		ret = -1;
		goto end;
	}

	header_offset = payload->buffer.size;

	DBG("Serializing uprobe event rule.");
	uprobe = container_of(rule, struct lttng_event_rule_userspace_probe, parent);

	name_len = strlen(uprobe->name) + 1;

	uprobe_comm.name_len = name_len;

	ret = lttng_dynamic_buffer_append(
			&payload->buffer, &uprobe_comm, sizeof(uprobe_comm));
	if (ret) {
		goto end;
	}
	ret = lttng_dynamic_buffer_append(
			&payload->buffer, uprobe->name, name_len);
	if (ret) {
		goto end;
	}

	size_before_probe = payload->buffer.size;

	/* This serialize return the size taken in the buffer. */
	ret = lttng_userspace_probe_location_serialize(
			uprobe->location, payload);
	if (ret < 0) {
		goto end;
	}

	/* Update the header regarding the probe size. */
	header = (struct lttng_event_rule_userspace_probe_comm
					*) ((char *) payload->buffer.data +
			header_offset);
	header->location_len = payload->buffer.size - size_before_probe;

	ret = 0;

end:
	return ret;
}

static bool lttng_event_rule_userspace_probe_is_equal(const struct lttng_event_rule *_a,
		const struct lttng_event_rule *_b)
{
	bool is_equal = false;
	struct lttng_event_rule_userspace_probe *a, *b;

	a = container_of(_a, struct lttng_event_rule_userspace_probe, parent);
	b = container_of(_b, struct lttng_event_rule_userspace_probe, parent);

	/* uprobe is invalid if this is not true. */
	assert(a->name);
	assert(b->name);
	if (strcmp(a->name, b->name)) {
		goto end;
	}

	assert(a->location);
	assert(b->location);
	is_equal = lttng_userspace_probe_location_is_equal(
			a->location, b->location);
end:
	return is_equal;
}

static enum lttng_error_code lttng_event_rule_userspace_probe_generate_filter_bytecode(
		struct lttng_event_rule *rule,
		const struct lttng_credentials *creds)
{
	/* Nothing to do. */
	return LTTNG_OK;
}

static const char *lttng_event_rule_userspace_probe_get_filter(
		const struct lttng_event_rule *rule)
{
	/* Unsupported. */
	return NULL;
}

static const struct lttng_bytecode *
lttng_event_rule_userspace_probe_get_filter_bytecode(const struct lttng_event_rule *rule)
{
	/* Unsupported. */
	return NULL;
}

static enum lttng_event_rule_generate_exclusions_status
lttng_event_rule_userspace_probe_generate_exclusions(const struct lttng_event_rule *rule,
		struct lttng_event_exclusion **exclusions)
{
	/* Unsupported. */
	*exclusions = NULL;
	return LTTNG_EVENT_RULE_GENERATE_EXCLUSIONS_STATUS_NONE;
}

static unsigned long
lttng_event_rule_userspace_probe_hash(
		const struct lttng_event_rule *rule)
{
	unsigned long hash;
	struct lttng_event_rule_userspace_probe *urule =
			container_of(rule, typeof(*urule), parent);

	hash = hash_key_ulong((void *) LTTNG_EVENT_RULE_TYPE_USERSPACE_PROBE,
			lttng_ht_seed);
	hash ^= hash_key_str(urule->name, lttng_ht_seed);
	hash ^= lttng_userspace_probe_location_hash(urule->location);

	return hash;
}

static
int userspace_probe_set_location(
		struct lttng_event_rule_userspace_probe *uprobe,
		const struct lttng_userspace_probe_location *location)
{
	int ret;
	struct lttng_userspace_probe_location *location_copy = NULL;

	if (!uprobe || !location || uprobe->location) {
		ret = -1;
		goto end;
	}

	location_copy = lttng_userspace_probe_location_copy(location);
	if (!location_copy) {
		ret = -1;
		goto end;
	}

	uprobe->location = location_copy;
	location_copy = NULL;
	ret = 0;
end:
	lttng_userspace_probe_location_destroy(location_copy);
	return ret;
}

struct lttng_event_rule *lttng_event_rule_userspace_probe_create(
		const struct lttng_userspace_probe_location *location)
{
	struct lttng_event_rule *rule = NULL;
	struct lttng_event_rule_userspace_probe *urule;

	urule = zmalloc(sizeof(struct lttng_event_rule_userspace_probe));
	if (!urule) {
		goto end;
	}

	rule = &urule->parent;
	lttng_event_rule_init(&urule->parent, LTTNG_EVENT_RULE_TYPE_USERSPACE_PROBE);
	urule->parent.validate = lttng_event_rule_userspace_probe_validate;
	urule->parent.serialize = lttng_event_rule_userspace_probe_serialize;
	urule->parent.equal = lttng_event_rule_userspace_probe_is_equal;
	urule->parent.destroy = lttng_event_rule_userspace_probe_destroy;
	urule->parent.generate_filter_bytecode =
			lttng_event_rule_userspace_probe_generate_filter_bytecode;
	urule->parent.get_filter = lttng_event_rule_userspace_probe_get_filter;
	urule->parent.get_filter_bytecode =
			lttng_event_rule_userspace_probe_get_filter_bytecode;
	urule->parent.generate_exclusions =
			lttng_event_rule_userspace_probe_generate_exclusions;
	urule->parent.hash = lttng_event_rule_userspace_probe_hash;

	if (userspace_probe_set_location(urule, location)) {
		lttng_event_rule_destroy(rule);
		rule = NULL;
	}

end:
	return rule;
}

LTTNG_HIDDEN
ssize_t lttng_event_rule_userspace_probe_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_event_rule **_event_rule)
{
	ssize_t ret, offset = 0;
	const struct lttng_event_rule_userspace_probe_comm *uprobe_comm;
	const char *name;
	struct lttng_buffer_view current_buffer_view;
	struct lttng_event_rule *rule = NULL;
	struct lttng_userspace_probe_location *location = NULL;
	enum lttng_event_rule_status status;

	if (!_event_rule) {
		ret = -1;
		goto end;
	}

	current_buffer_view = lttng_buffer_view_from_view(
			&view->buffer, offset, sizeof(*uprobe_comm));
	if (!lttng_buffer_view_is_valid(&current_buffer_view)) {
		ERR("Failed to initialize from malformed event rule uprobe: buffer too short to contain header");
		ret = -1;
		goto end;
	}

	uprobe_comm = (typeof(uprobe_comm)) current_buffer_view.data;

	/* Skip to payload. */
	offset += current_buffer_view.size;

	/* Map the name. */
	current_buffer_view = lttng_buffer_view_from_view(
			&view->buffer, offset, uprobe_comm->name_len);
	if (!lttng_buffer_view_is_valid(&current_buffer_view)) {
		ret = -1;
		goto end;
	}

	name = current_buffer_view.data;
	if (!lttng_buffer_view_contains_string(&current_buffer_view, name,
			uprobe_comm->name_len)) {
		ret = -1;
		goto end;
	}

	/* Skip after the name. */
	offset += uprobe_comm->name_len;

	/* Map the location. */
	{
		struct lttng_payload_view current_payload_view =
				lttng_payload_view_from_view(view, offset,
						uprobe_comm->location_len);

		if (!lttng_payload_view_is_valid(&current_payload_view)) {
			ERR("Failed to initialize from malformed event rule uprobe: buffer too short to contain location");
			ret = -1;
			goto end;
		}

		ret = lttng_userspace_probe_location_create_from_payload(
				&current_payload_view, &location);
		if (ret < 0) {
			ret = -1;
			goto end;
		}
	}

	assert(ret == uprobe_comm->location_len);

	/* Skip after the location. */
	offset += uprobe_comm->location_len;

	rule = lttng_event_rule_userspace_probe_create(location);
	if (!rule) {
		ERR("Failed to create event rule uprobe.");
		ret = -1;
		goto end;
	}

	status = lttng_event_rule_userspace_probe_set_event_name(rule, name);
	if (status != LTTNG_EVENT_RULE_STATUS_OK) {
		ret = -1;
		goto end;
	}

	if (!lttng_event_rule_userspace_probe_validate(rule)) {
		ret = -1;
		goto end;
	}

	*_event_rule = rule;
	rule = NULL;
	ret = offset;
end:
	lttng_userspace_probe_location_destroy(location);
	lttng_event_rule_destroy(rule);
	return ret;
}


enum lttng_event_rule_status lttng_event_rule_userspace_probe_get_location(
		const struct lttng_event_rule *rule,
		const struct lttng_userspace_probe_location **location)
{
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_UPROBE_EVENT_RULE(rule) || !location) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	*location = lttng_event_rule_userspace_probe_get_location_mutable(rule);
	if (!*location) {
		status = LTTNG_EVENT_RULE_STATUS_UNSET;
		goto end;
	}

end:
	return status;
}

LTTNG_HIDDEN
struct lttng_userspace_probe_location *
lttng_event_rule_userspace_probe_get_location_mutable(
		const struct lttng_event_rule *rule)
{
	struct lttng_event_rule_userspace_probe *uprobe;

	assert(rule);
	uprobe = container_of(rule, struct lttng_event_rule_userspace_probe, parent);

	return uprobe->location;
}

enum lttng_event_rule_status lttng_event_rule_userspace_probe_set_event_name(
		struct lttng_event_rule *rule, const char *name)
{
	char *name_copy = NULL;
	struct lttng_event_rule_userspace_probe *uprobe;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_UPROBE_EVENT_RULE(rule) || !name ||
			strlen(name) == 0) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	uprobe = container_of(rule, struct lttng_event_rule_userspace_probe, parent);
	name_copy = strdup(name);
	if (!name_copy) {
		status = LTTNG_EVENT_RULE_STATUS_ERROR;
		goto end;
	}

	if (uprobe->name) {
		free(uprobe->name);
	}

	uprobe->name = name_copy;
	name_copy = NULL;
end:
	return status;
}

enum lttng_event_rule_status lttng_event_rule_userspace_probe_get_event_name(
		const struct lttng_event_rule *rule, const char **name)
{
	struct lttng_event_rule_userspace_probe *uprobe;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_UPROBE_EVENT_RULE(rule) || !name) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	uprobe = container_of(rule, struct lttng_event_rule_userspace_probe, parent);
	if (!uprobe->name) {
		status = LTTNG_EVENT_RULE_STATUS_UNSET;
		goto end;
	}

	*name = uprobe->name;
end:
	return status;
}
