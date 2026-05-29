/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/error.hpp>
#include <common/macros.hpp>
#include <common/mi-lttng.hpp>
#include <common/payload-view.hpp>
#include <common/payload.hpp>

#include <lttng/action/action-internal.hpp>
#include <lttng/action/increment-map-value-internal.hpp>
#include <lttng/action/increment-map-value.h>
#include <lttng/action/key-template-internal.hpp>
#include <lttng/action/key-template.h>

#define IS_INCREMENT_MAP_VALUE_ACTION(action) \
	(lttng_action_get_type(action) == LTTNG_ACTION_TYPE_INCREMENT_MAP_VALUE)

namespace {
struct lttng_action_increment_map_value {
	struct lttng_action parent;

	/*
	 * Target map channel type. `channel_type` is only meaningful when
	 * `channel_type_set` is true, since `enum lttng_map_channel_type`
	 * has no "unset" enumerator.
	 */
	enum lttng_map_channel_type channel_type;
	bool channel_type_set;

	/* Owned by this. */
	char *session_name;
	char *channel_name;
	struct lttng_key_template *key_template;
};

struct lttng_action_increment_map_value_comm {
	/*
	 * enum lttng_map_channel_type: LTTNG_MAP_CHANNEL_TYPE_KERNEL or
	 * LTTNG_MAP_CHANNEL_TYPE_USER.
	 */
	int8_t channel_type;

	/* String lengths include the trailing \0. */
	uint32_t session_name_len;
	uint32_t channel_name_len;

	/*
	 * Variable data:
	 *
	 *   - session name string (null-terminated)
	 *   - channel name string (null-terminated)
	 *   - serialized key template
	 */
	char data[];
} LTTNG_PACKED;

struct lttng_action_increment_map_value *
action_increment_map_value_from_action(struct lttng_action *action)
{
	LTTNG_ASSERT(action);

	return lttng::utils::container_of(action, &lttng_action_increment_map_value::parent);
}

const struct lttng_action_increment_map_value *
action_increment_map_value_from_action_const(const struct lttng_action *action)
{
	LTTNG_ASSERT(action);

	return lttng::utils::container_of(action, &lttng_action_increment_map_value::parent);
}

const char *map_channel_type_string(enum lttng_map_channel_type type)
{
	switch (type) {
	case LTTNG_MAP_CHANNEL_TYPE_KERNEL:
		return "kernel";
	case LTTNG_MAP_CHANNEL_TYPE_USER:
		return "user";
	default:
		abort();
	}
}

bool lttng_action_increment_map_value_validate(struct lttng_action *action)
{
	bool valid = false;
	struct lttng_action_increment_map_value *action_incr;

	if (!action) {
		goto end;
	}

	action_incr = action_increment_map_value_from_action(action);

	/* The target session name, channel name and key template are mandatory. */
	if (!action_incr->session_name || strlen(action_incr->session_name) == 0) {
		goto end;
	}

	if (!action_incr->channel_name || strlen(action_incr->channel_name) == 0) {
		goto end;
	}

	if (!action_incr->key_template) {
		goto end;
	}

	/* The target map channel type is mandatory. */
	if (!action_incr->channel_type_set) {
		goto end;
	}

	valid = true;
end:
	return valid;
}

bool lttng_action_increment_map_value_is_equal(const struct lttng_action *_a,
					       const struct lttng_action *_b)
{
	bool is_equal = false;
	const struct lttng_action_increment_map_value *a, *b;

	a = action_increment_map_value_from_action_const(_a);
	b = action_increment_map_value_from_action_const(_b);

	/* The action is invalid unless these are set. */
	LTTNG_ASSERT(a->session_name);
	LTTNG_ASSERT(b->session_name);
	LTTNG_ASSERT(a->channel_name);
	LTTNG_ASSERT(b->channel_name);
	LTTNG_ASSERT(a->key_template);
	LTTNG_ASSERT(b->key_template);

	if (a->channel_type != b->channel_type) {
		goto end;
	}

	if (strcmp(a->session_name, b->session_name) != 0) {
		goto end;
	}

	if (strcmp(a->channel_name, b->channel_name) != 0) {
		goto end;
	}

	if (*a->key_template != *b->key_template) {
		goto end;
	}

	is_equal = true;
end:
	return is_equal;
}

int lttng_action_increment_map_value_serialize(struct lttng_action *action,
					       struct lttng_payload *payload)
{
	struct lttng_action_increment_map_value *action_incr;
	struct lttng_action_increment_map_value_comm comm;
	size_t session_name_len, channel_name_len;
	int ret;

	LTTNG_ASSERT(action);
	LTTNG_ASSERT(payload);

	action_incr = action_increment_map_value_from_action(action);

	LTTNG_ASSERT(action_incr->session_name);
	LTTNG_ASSERT(action_incr->channel_name);
	LTTNG_ASSERT(action_incr->key_template);

	DBG("Serializing increment-map-value action: session-name=`%s`, channel-name=`%s`, channel-type=%d",
	    action_incr->session_name,
	    action_incr->channel_name,
	    (int) action_incr->channel_type);

	session_name_len = strlen(action_incr->session_name) + 1;
	channel_name_len = strlen(action_incr->channel_name) + 1;

	comm.channel_type = (int8_t) action_incr->channel_type;
	comm.session_name_len = session_name_len;
	comm.channel_name_len = channel_name_len;

	ret = lttng_dynamic_buffer_append(&payload->buffer, &comm, sizeof(comm));
	if (ret) {
		ret = -1;
		goto end;
	}

	ret = lttng_dynamic_buffer_append(
		&payload->buffer, action_incr->session_name, session_name_len);
	if (ret) {
		ret = -1;
		goto end;
	}

	ret = lttng_dynamic_buffer_append(
		&payload->buffer, action_incr->channel_name, channel_name_len);
	if (ret) {
		ret = -1;
		goto end;
	}

	ret = action_incr->key_template->serialize(*payload);
	if (ret) {
		ret = -1;
		goto end;
	}

	ret = 0;
end:
	return ret;
}

void lttng_action_increment_map_value_destroy(struct lttng_action *action)
{
	struct lttng_action_increment_map_value *action_incr;

	if (!action) {
		goto end;
	}

	action_incr = action_increment_map_value_from_action(action);

	free(action_incr->session_name);
	free(action_incr->channel_name);
	lttng_key_template_destroy(action_incr->key_template);
	free(action_incr);

end:
	return;
}

enum lttng_error_code
lttng_action_increment_map_value_mi_serialize(const struct lttng_action *action,
					      struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;
	const char *session_name = nullptr;
	const char *channel_name = nullptr;
	enum lttng_map_channel_type channel_type = LTTNG_MAP_CHANNEL_TYPE_KERNEL;
	const struct lttng_key_template *key_template = nullptr;
	char *key_template_str = nullptr;
	enum lttng_action_status action_status;

	LTTNG_ASSERT(action);
	LTTNG_ASSERT(IS_INCREMENT_MAP_VALUE_ACTION(action));
	LTTNG_ASSERT(writer);

	action_status =
		lttng_action_increment_map_value_get_target_session_name(action, &session_name);
	LTTNG_ASSERT(action_status == LTTNG_ACTION_STATUS_OK);

	action_status =
		lttng_action_increment_map_value_get_target_channel_name(action, &channel_name);
	LTTNG_ASSERT(action_status == LTTNG_ACTION_STATUS_OK);

	action_status =
		lttng_action_increment_map_value_get_target_channel_type(action, &channel_type);
	LTTNG_ASSERT(action_status == LTTNG_ACTION_STATUS_OK);

	action_status = lttng_action_increment_map_value_get_key_template(action, &key_template);
	LTTNG_ASSERT(action_status == LTTNG_ACTION_STATUS_OK);

	if (lttng_key_template_to_string(key_template, &key_template_str) !=
	    LTTNG_KEY_TEMPLATE_STATUS_OK) {
		ret_code = LTTNG_ERR_NOMEM;
		goto end;
	}

	/* Open action increment-map-value element. */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_action_increment_map_value);
	if (ret) {
		goto mi_error;
	}

	/* Target session name. */
	ret = mi_lttng_writer_write_element_string(
		writer, mi_lttng_element_session_name, session_name);
	if (ret) {
		goto mi_error;
	}

	/* Target map channel type. */
	ret = mi_lttng_writer_write_element_string(
		writer,
		mi_lttng_element_action_increment_map_value_channel_type,
		map_channel_type_string(channel_type));
	if (ret) {
		goto mi_error;
	}

	/* Target channel name. */
	ret = mi_lttng_writer_write_element_string(
		writer, mi_lttng_element_action_increment_map_value_channel_name, channel_name);
	if (ret) {
		goto mi_error;
	}

	/* Key template. */
	ret = mi_lttng_writer_write_element_string(
		writer, mi_lttng_element_action_increment_map_value_key_template, key_template_str);
	if (ret) {
		goto mi_error;
	}

	/* Close action increment-map-value element. */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto mi_error;
	}

	ret_code = LTTNG_OK;
	goto end;

mi_error:
	ret_code = LTTNG_ERR_MI_IO_FAIL;
end:
	free(key_template_str);
	return ret_code;
}
} /* namespace */

struct lttng_action *lttng_action_increment_map_value_create(void)
{
	struct lttng_action_increment_map_value *action_incr;

	action_incr = zmalloc<lttng_action_increment_map_value>();
	if (!action_incr) {
		goto end;
	}

	lttng_action_init(&action_incr->parent,
			  LTTNG_ACTION_TYPE_INCREMENT_MAP_VALUE,
			  lttng_action_increment_map_value_validate,
			  lttng_action_increment_map_value_serialize,
			  lttng_action_increment_map_value_is_equal,
			  lttng_action_increment_map_value_destroy,
			  nullptr,
			  lttng_action_generic_add_error_query_results,
			  lttng_action_increment_map_value_mi_serialize);

end:
	return action_incr ? &action_incr->parent : nullptr;
}

ssize_t lttng_action_increment_map_value_create_from_payload(struct lttng_payload_view *view,
							     struct lttng_action **p_action)
{
	ssize_t consumed_len;
	const struct lttng_action_increment_map_value_comm *comm;
	const char *session_name;
	const char *channel_name;
	struct lttng_action *action = nullptr;
	struct lttng_action_increment_map_value *action_incr;
	std::unique_ptr<lttng_key_template> key_template;
	enum lttng_action_status status;
	size_t offset;

	comm = (typeof(comm)) view->buffer.data;
	session_name = (const char *) &comm->data;

	if (!lttng_buffer_view_contains_string(
		    &view->buffer, session_name, comm->session_name_len)) {
		consumed_len = -1;
		goto end;
	}

	channel_name = session_name + comm->session_name_len;
	if (!lttng_buffer_view_contains_string(
		    &view->buffer, channel_name, comm->channel_name_len)) {
		consumed_len = -1;
		goto end;
	}

	offset = sizeof(*comm) + comm->session_name_len + comm->channel_name_len;
	{
		struct lttng_payload_view tmpl_view =
			lttng_payload_view_from_view(view, offset, -1);
		const ssize_t tmpl_consumed_len =
			lttng_key_template::create_from_payload(tmpl_view, key_template);

		if (tmpl_consumed_len < 0) {
			consumed_len = -1;
			goto end;
		}

		offset += tmpl_consumed_len;
	}

	action = lttng_action_increment_map_value_create();
	if (!action) {
		consumed_len = -1;
		goto end;
	}

	/* The setter rejects any byte that isn't a supported map channel type. */
	status = lttng_action_increment_map_value_set_target_channel_type(
		action, (enum lttng_map_channel_type) comm->channel_type);
	if (status != LTTNG_ACTION_STATUS_OK) {
		consumed_len = -1;
		goto end;
	}

	status = lttng_action_increment_map_value_set_target_session_name(action, session_name);
	if (status != LTTNG_ACTION_STATUS_OK) {
		consumed_len = -1;
		goto end;
	}

	status = lttng_action_increment_map_value_set_target_channel_name(action, channel_name);
	if (status != LTTNG_ACTION_STATUS_OK) {
		consumed_len = -1;
		goto end;
	}

	/*
	 * Move ownership of the deserialized template into the action directly,
	 * bypassing the public setter's copy.
	 */
	action_incr = action_increment_map_value_from_action(action);
	action_incr->key_template = key_template.release();

	consumed_len = offset;
	*p_action = action;
	action = nullptr;

end:
	lttng_action_increment_map_value_destroy(action);
	return consumed_len;
}

namespace {
enum lttng_action_status set_string_field(struct lttng_action *action,
					  const char *value,
					  char *lttng_action_increment_map_value::*member)
{
	struct lttng_action_increment_map_value *action_incr;
	enum lttng_action_status status;
	char *value_copy = nullptr;

	if (!action || !IS_INCREMENT_MAP_VALUE_ACTION(action) || !value || strlen(value) == 0) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	value_copy = strdup(value);
	if (!value_copy) {
		status = LTTNG_ACTION_STATUS_ERROR;
		goto end;
	}

	action_incr = action_increment_map_value_from_action(action);
	free(action_incr->*member);
	action_incr->*member = value_copy;
	value_copy = nullptr;

	status = LTTNG_ACTION_STATUS_OK;
end:
	free(value_copy);
	return status;
}
} /* namespace */

enum lttng_action_status
lttng_action_increment_map_value_set_target_session_name(struct lttng_action *action,
							 const char *session_name)
{
	return set_string_field(
		action, session_name, &lttng_action_increment_map_value::session_name);
}

enum lttng_action_status
lttng_action_increment_map_value_get_target_session_name(const struct lttng_action *action,
							 const char **session_name)
{
	const struct lttng_action_increment_map_value *action_incr;

	if (!action || !IS_INCREMENT_MAP_VALUE_ACTION(action) || !session_name) {
		return LTTNG_ACTION_STATUS_INVALID;
	}

	action_incr = action_increment_map_value_from_action_const(action);
	if (!action_incr->session_name) {
		return LTTNG_ACTION_STATUS_UNSET;
	}

	*session_name = action_incr->session_name;
	return LTTNG_ACTION_STATUS_OK;
}

enum lttng_action_status
lttng_action_increment_map_value_set_target_channel_name(struct lttng_action *action,
							 const char *channel_name)
{
	return set_string_field(
		action, channel_name, &lttng_action_increment_map_value::channel_name);
}

enum lttng_action_status
lttng_action_increment_map_value_get_target_channel_name(const struct lttng_action *action,
							 const char **channel_name)
{
	const struct lttng_action_increment_map_value *action_incr;

	if (!action || !IS_INCREMENT_MAP_VALUE_ACTION(action) || !channel_name) {
		return LTTNG_ACTION_STATUS_INVALID;
	}

	action_incr = action_increment_map_value_from_action_const(action);
	if (!action_incr->channel_name) {
		return LTTNG_ACTION_STATUS_UNSET;
	}

	*channel_name = action_incr->channel_name;
	return LTTNG_ACTION_STATUS_OK;
}

enum lttng_action_status
lttng_action_increment_map_value_set_target_channel_type(struct lttng_action *action,
							 enum lttng_map_channel_type type)
{
	struct lttng_action_increment_map_value *action_incr;

	if (!action || !IS_INCREMENT_MAP_VALUE_ACTION(action) ||
	    (type != LTTNG_MAP_CHANNEL_TYPE_KERNEL && type != LTTNG_MAP_CHANNEL_TYPE_USER)) {
		return LTTNG_ACTION_STATUS_INVALID;
	}

	action_incr = action_increment_map_value_from_action(action);
	action_incr->channel_type = type;
	action_incr->channel_type_set = true;
	return LTTNG_ACTION_STATUS_OK;
}

enum lttng_action_status
lttng_action_increment_map_value_get_target_channel_type(const struct lttng_action *action,
							 enum lttng_map_channel_type *type)
{
	const struct lttng_action_increment_map_value *action_incr;

	if (!action || !IS_INCREMENT_MAP_VALUE_ACTION(action) || !type) {
		return LTTNG_ACTION_STATUS_INVALID;
	}

	action_incr = action_increment_map_value_from_action_const(action);
	if (!action_incr->channel_type_set) {
		return LTTNG_ACTION_STATUS_UNSET;
	}

	*type = action_incr->channel_type;
	return LTTNG_ACTION_STATUS_OK;
}

enum lttng_action_status
lttng_action_increment_map_value_set_key_template(struct lttng_action *action,
						  const struct lttng_key_template *key_template)
{
	struct lttng_action_increment_map_value *action_incr;
	std::unique_ptr<lttng_key_template> copy;

	if (!action || !IS_INCREMENT_MAP_VALUE_ACTION(action) || !key_template) {
		return LTTNG_ACTION_STATUS_INVALID;
	}

	try {
		copy = lttng::make_unique<lttng_key_template>(*key_template);
	} catch (const std::exception& e) {
		ERR_FMT("Failed to copy key template: {}", e.what());
		return LTTNG_ACTION_STATUS_ERROR;
	}

	action_incr = action_increment_map_value_from_action(action);
	lttng_key_template_destroy(action_incr->key_template);
	action_incr->key_template = copy.release();
	return LTTNG_ACTION_STATUS_OK;
}

enum lttng_action_status
lttng_action_increment_map_value_get_key_template(const struct lttng_action *action,
						  const struct lttng_key_template **key_template)
{
	const struct lttng_action_increment_map_value *action_incr;

	if (!action || !IS_INCREMENT_MAP_VALUE_ACTION(action) || !key_template) {
		return LTTNG_ACTION_STATUS_INVALID;
	}

	action_incr = action_increment_map_value_from_action_const(action);
	if (!action_incr->key_template) {
		return LTTNG_ACTION_STATUS_UNSET;
	}

	*key_template = action_incr->key_template;
	return LTTNG_ACTION_STATUS_OK;
}
