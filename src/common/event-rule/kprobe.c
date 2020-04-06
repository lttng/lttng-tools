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
#include <ctype.h>
#include <lttng/constant.h>
#include <lttng/event-rule/event-rule-internal.h>
#include <lttng/event-rule/kprobe-internal.h>
#include <lttng/kernel-probe.h>
#include <lttng/kernel-probe-internal.h>
#include <stdio.h>

#define IS_KPROBE_EVENT_RULE(rule) \
	(lttng_event_rule_get_type(rule) == LTTNG_EVENT_RULE_TYPE_KPROBE)

#if (LTTNG_SYMBOL_NAME_LEN == 256)
#define LTTNG_SYMBOL_NAME_LEN_SCANF_IS_A_BROKEN_API "255"
#endif

static void lttng_event_rule_kprobe_destroy(struct lttng_event_rule *rule)
{
	struct lttng_event_rule_kprobe *kprobe;

	kprobe = container_of(rule, struct lttng_event_rule_kprobe, parent);

	lttng_kernel_probe_location_destroy(kprobe->location);
	free(kprobe->name);
	free(kprobe);
}

static bool lttng_event_rule_kprobe_validate(
		const struct lttng_event_rule *rule)
{
	bool valid = false;
	struct lttng_event_rule_kprobe *kprobe;

	if (!rule) {
		goto end;
	}

	kprobe = container_of(rule, struct lttng_event_rule_kprobe, parent);

	/* Required field. */
	if (!kprobe->name) {
		ERR("Invalid name event rule: a name must be set.");
		goto end;
	}

	/* Required field. */
	if(!kprobe->location) {
		ERR("Invalid name event rule: a location must be set.");
		goto end;
	}

	valid = true;
end:
	return valid;
}

static int lttng_event_rule_kprobe_serialize(
		const struct lttng_event_rule *rule,
		struct lttng_payload *payload)
{
	int ret;
	size_t name_len, header_offset, size_before_location;
	struct lttng_event_rule_kprobe *kprobe;
	struct lttng_event_rule_kprobe_comm kprobe_comm;
	struct lttng_event_rule_kprobe_comm *header;

	if (!rule || !IS_KPROBE_EVENT_RULE(rule)) {
		ret = -1;
		goto end;
	}

	header_offset = payload->buffer.size;

	DBG("Serializing kprobe event rule.");
	kprobe = container_of(rule, struct lttng_event_rule_kprobe, parent);

	name_len = strlen(kprobe->name) + 1;
	kprobe_comm.name_len = name_len;

	ret = lttng_dynamic_buffer_append(
			&payload->buffer, &kprobe_comm, sizeof(kprobe_comm));
	if (ret) {
		goto end;
	}

	ret = lttng_dynamic_buffer_append(&payload->buffer, kprobe->name, name_len);
	if (ret) {
		goto end;
	}

	size_before_location = payload->buffer.size;

	ret = lttng_kernel_probe_location_serialize(kprobe->location, payload);
	if (ret < 0) {
		goto end;
	}

	/* Update the header regarding the probe size. */
	header = (struct lttng_event_rule_kprobe_comm*) (
			(char *) payload->buffer.data + header_offset);
	header->location_len = payload->buffer.size - size_before_location;

	ret = 0;

end:
	return ret;
}

static bool lttng_event_rule_kprobe_is_equal(const struct lttng_event_rule *_a,
		const struct lttng_event_rule *_b)
{
	bool is_equal = false;
	struct lttng_event_rule_kprobe *a, *b;

	a = container_of(_a, struct lttng_event_rule_kprobe, parent);
	b = container_of(_b, struct lttng_event_rule_kprobe, parent);

	/* Quick checks */
	if (!!a->name != !!b->name) {
		goto end;
	}

	/* Long check */
	assert(a->name);
	assert(b->name);
	if (strcmp(a->name, b->name)) {
		goto end;
	}

	is_equal = lttng_kernel_probe_location_is_equal(
			a->location, b->location);
end:
	return is_equal;
}

static enum lttng_error_code lttng_event_rule_kprobe_generate_filter_bytecode(
		struct lttng_event_rule *rule,
		const struct lttng_credentials *creds)
{
	/* Nothing to do. */
	return LTTNG_OK;
}

static const char *lttng_event_rule_kprobe_get_filter(
		const struct lttng_event_rule *rule)
{
	/* Not supported. */
	return NULL;
}

static const struct lttng_bytecode *
lttng_event_rule_kprobe_get_filter_bytecode(const struct lttng_event_rule *rule)
{
	/* Not supported. */
	return NULL;
}

static enum lttng_event_rule_generate_exclusions_status
lttng_event_rule_kprobe_generate_exclusions(const struct lttng_event_rule *rule,
		struct lttng_event_exclusion **exclusions)
{
	/* Not supported. */
	*exclusions = NULL;
	return LTTNG_EVENT_RULE_GENERATE_EXCLUSIONS_STATUS_NONE;
}

static unsigned long
lttng_event_rule_kprobe_hash(
		const struct lttng_event_rule *rule)
{
	unsigned long hash;
	struct lttng_event_rule_kprobe *krule =
			container_of(rule, typeof(*krule), parent);

	hash = hash_key_ulong((void *) LTTNG_EVENT_RULE_TYPE_KPROBE,
			lttng_ht_seed);
	hash ^= hash_key_str(krule->name, lttng_ht_seed);
	hash ^= lttng_kernel_probe_location_hash(krule->location);

	return hash;
}

struct lttng_event_rule *lttng_event_rule_kprobe_create(void)
{
	struct lttng_event_rule *rule = NULL;
	struct lttng_event_rule_kprobe *krule;

	krule = zmalloc(sizeof(struct lttng_event_rule_kprobe));
	if (!krule) {
		goto end;
	}

	rule = &krule->parent;
	lttng_event_rule_init(&krule->parent, LTTNG_EVENT_RULE_TYPE_KPROBE);
	krule->parent.validate = lttng_event_rule_kprobe_validate;
	krule->parent.serialize = lttng_event_rule_kprobe_serialize;
	krule->parent.equal = lttng_event_rule_kprobe_is_equal;
	krule->parent.destroy = lttng_event_rule_kprobe_destroy;
	krule->parent.generate_filter_bytecode =
			lttng_event_rule_kprobe_generate_filter_bytecode;
	krule->parent.get_filter = lttng_event_rule_kprobe_get_filter;
	krule->parent.get_filter_bytecode =
			lttng_event_rule_kprobe_get_filter_bytecode;
	krule->parent.generate_exclusions =
			lttng_event_rule_kprobe_generate_exclusions;
	krule->parent.hash = lttng_event_rule_kprobe_hash;
end:
	return rule;
}

LTTNG_HIDDEN
ssize_t lttng_event_rule_kprobe_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_event_rule **_event_rule)
{
	ssize_t ret, offset = 0;
	enum lttng_event_rule_status status;
	const struct lttng_event_rule_kprobe_comm *kprobe_comm;
	const char *name;
	struct lttng_buffer_view current_buffer_view;
	struct lttng_event_rule *rule = NULL;
	struct lttng_event_rule_kprobe *kprobe = NULL;
	struct lttng_kernel_probe_location *location;

	if (!_event_rule) {
		ret = -1;
		goto end;
	}

	current_buffer_view = lttng_buffer_view_from_view(
			&view->buffer, offset, sizeof(*kprobe_comm));
	if (!lttng_buffer_view_is_valid(&current_buffer_view)) {
		ERR("Failed to initialize from malformed event rule kprobe: buffer too short to contain header.");
		ret = -1;
		goto end;
	}

	kprobe_comm = (typeof(kprobe_comm)) current_buffer_view.data;

	rule = lttng_event_rule_kprobe_create();
	if (!rule) {
		ERR("Failed to create event rule kprobe.");
		ret = -1;
		goto end;
	}

	kprobe = container_of(rule, struct lttng_event_rule_kprobe, parent);

	/* Skip to payload */
	offset += current_buffer_view.size;

	{
		/* Map the name. */
		struct lttng_payload_view current_payload_view =
				lttng_payload_view_from_view(view, offset,
						kprobe_comm->name_len);

		if (!lttng_payload_view_is_valid(&current_payload_view)) {
			ret = -1;
			goto end;
		}

		name = current_payload_view.buffer.data;
		if (!lttng_buffer_view_contains_string(
				&current_payload_view.buffer, name,
				kprobe_comm->name_len)) {
			ret = -1;
			goto end;
		}
	}

	/* Skip after the name. */
	offset += kprobe_comm->name_len;

	/* Map the kernel probe location. */
	{
		struct lttng_payload_view current_payload_view =
				lttng_payload_view_from_view(view, offset,
						kprobe_comm->location_len);

		if (!lttng_payload_view_is_valid(&current_payload_view)) {
			ret = -1;
			goto end;
		}

		ret = lttng_kernel_probe_location_create_from_payload(
				&current_payload_view, &location);
		if (ret < 0) {
			ret = -1;
			goto end;
		}
	}

	if (ret != kprobe_comm->location_len) {
		ret = -1;
		goto end;
	}

	kprobe->location = location;

	/* Skip after the location */
	offset += kprobe_comm->location_len;

	status = lttng_event_rule_kprobe_set_name(rule, name);
	if (status != LTTNG_EVENT_RULE_STATUS_OK) {
		ERR("Failed to set event rule kprobe name.");
		ret = -1;
		goto end;
	}

	*_event_rule = rule;
	rule = NULL;
	ret = offset;
end:
	lttng_event_rule_destroy(rule);
	return ret;
}

enum lttng_event_rule_status lttng_event_rule_kprobe_set_location(
		struct lttng_event_rule *rule,
		const struct lttng_kernel_probe_location *location)
{
	struct lttng_kernel_probe_location *location_copy = NULL;
	struct lttng_event_rule_kprobe *kprobe;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_KPROBE_EVENT_RULE(rule) || !location) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	kprobe = container_of(rule, struct lttng_event_rule_kprobe, parent);
	location_copy = lttng_kernel_probe_location_copy(location);
	if (!location_copy) {
		status = LTTNG_EVENT_RULE_STATUS_ERROR;
		goto end;
	}

	if (kprobe->location) {
		lttng_kernel_probe_location_destroy(kprobe->location);
	}

	kprobe->location = location_copy;
	location_copy = NULL;
end:
	lttng_kernel_probe_location_destroy(location_copy);
	return status;
}

enum lttng_event_rule_status lttng_event_rule_kprobe_get_location(
		const struct lttng_event_rule *rule,
		const struct lttng_kernel_probe_location **location)
{
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;
	struct lttng_event_rule_kprobe *kprobe;

	if (!rule || !IS_KPROBE_EVENT_RULE(rule) || !location) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	kprobe = container_of(rule, struct lttng_event_rule_kprobe, parent);
	*location = kprobe->location;

	if (!*location) {
		status = LTTNG_EVENT_RULE_STATUS_UNSET;
		goto end;
	}

end:
	return status;
}

enum lttng_event_rule_status lttng_event_rule_kprobe_set_name(
		struct lttng_event_rule *rule, const char *name)
{
	char *name_copy = NULL;
	struct lttng_event_rule_kprobe *kprobe;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_KPROBE_EVENT_RULE(rule) || !name ||
			strlen(name) == 0) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	kprobe = container_of(rule, struct lttng_event_rule_kprobe, parent);
	name_copy = strdup(name);
	if (!name_copy) {
		status = LTTNG_EVENT_RULE_STATUS_ERROR;
		goto end;
	}

	free(kprobe->name);

	kprobe->name = name_copy;
	name_copy = NULL;
end:
	return status;
}

enum lttng_event_rule_status lttng_event_rule_kprobe_get_name(
		const struct lttng_event_rule *rule, const char **name)
{
	struct lttng_event_rule_kprobe *kprobe;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_KPROBE_EVENT_RULE(rule) || !name) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	kprobe = container_of(rule, struct lttng_event_rule_kprobe, parent);
	if (!kprobe->name) {
		status = LTTNG_EVENT_RULE_STATUS_UNSET;
		goto end;
	}

	*name = kprobe->name;
end:
	return status;
}
