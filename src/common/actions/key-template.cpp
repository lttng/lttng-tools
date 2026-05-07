/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/dynamic-buffer.hpp>
#include <common/error.hpp>
#include <common/format.hpp>
#include <common/macros.hpp>
#include <common/make-unique.hpp>
#include <common/payload-view.hpp>
#include <common/payload.hpp>

#include <lttng/action/key-template-internal.hpp>
#include <lttng/action/key-template.h>

#include <cstdlib>
#include <cstring>
#include <exception>
#include <inttypes.h>
#include <memory>
#include <stdint.h>
#include <string>
#include <vector>

namespace details = lttng::action::details;

namespace {
struct template_comm {
	uint32_t segment_count;

	/*
	 * Followed by `segment_count` serialized segments. Each segment is a 1-byte
	 * type discriminator followed, for literal segments only, by a length-prefixed
	 * NUL-terminated string.
	 */
} LTTNG_PACKED;

const char *placeholder_name(details::key_template_segment_type type) noexcept
{
	switch (type) {
	case details::key_template_segment_type::EVENT_NAME:
		return "event_name";
	case details::key_template_segment_type::PROVIDER_NAME:
		return "provider_name";
	case details::key_template_segment_type::LITERAL:
		break;
	}

	std::abort();
}

std::unique_ptr<details::key_template_segment> make_placeholder_from_name(const std::string& name)
{
	if (name == "event_name") {
		return lttng::make_unique<details::key_template_placeholder_segment>(
			details::key_template_segment_type::EVENT_NAME);
	}

	if (name == "provider_name") {
		return lttng::make_unique<details::key_template_placeholder_segment>(
			details::key_template_segment_type::PROVIDER_NAME);
	}

	return nullptr;
}

std::unique_ptr<lttng_key_template> parse_template_string(const char *str)
{
	LTTNG_ASSERT(str);

	auto tmpl = lttng::make_unique<lttng_key_template>();
	std::string literal_buf;
	std::string placeholder_name_buf;

	enum class state {
		LITERAL,
		SEEN_OPEN_BRACE,
		IN_PLACEHOLDER,
		SEEN_CLOSE_BRACE,
	};

	state s = state::LITERAL;

	const auto flush_literal = [&]() {
		if (literal_buf.empty()) {
			return;
		}

		tmpl->segments.emplace_back(
			lttng::make_unique<details::key_template_literal_segment>(
				std::move(literal_buf)));
		literal_buf.clear();
	};

	for (const char *p = str; *p != '\0'; ++p) {
		const char c = *p;

		switch (s) {
		case state::LITERAL:
			if (c == '{') {
				s = state::SEEN_OPEN_BRACE;
			} else if (c == '}') {
				s = state::SEEN_CLOSE_BRACE;
			} else {
				literal_buf.push_back(c);
			}
			break;
		case state::SEEN_OPEN_BRACE:
			if (c == '{') {
				/* Escaped `{`. */
				literal_buf.push_back('{');
				s = state::LITERAL;
			} else if (c == '}') {
				/* Empty placeholder name is rejected. */
				return nullptr;
			} else {
				flush_literal();
				placeholder_name_buf.push_back(c);
				s = state::IN_PLACEHOLDER;
			}
			break;
		case state::IN_PLACEHOLDER:
			if (c == '}') {
				auto placeholder = make_placeholder_from_name(placeholder_name_buf);

				if (!placeholder) {
					ERR_FMT("Unknown key template placeholder: name=`{}`",
						placeholder_name_buf);
					return nullptr;
				}

				tmpl->segments.emplace_back(std::move(placeholder));
				placeholder_name_buf.clear();
				s = state::LITERAL;
			} else if (c == '{') {
				/* Nested `{` is not allowed. */
				return nullptr;
			} else {
				placeholder_name_buf.push_back(c);
			}
			break;
		case state::SEEN_CLOSE_BRACE:
			if (c == '}') {
				/* Escaped `}`. */
				literal_buf.push_back('}');
				s = state::LITERAL;
			} else {
				/* Lone `}` outside of a placeholder is rejected. */
				return nullptr;
			}
			break;
		}
	}

	if (s != state::LITERAL) {
		/* Trailing `{`, unterminated placeholder, or trailing lone `}`. */
		return nullptr;
	}

	flush_literal();
	return tmpl;
}

std::string render_template(const lttng_key_template& tmpl)
{
	std::string out;

	for (const auto& segment : tmpl.segments) {
		switch (segment->type) {
		case details::key_template_segment_type::LITERAL:
		{
			const auto& literal =
				static_cast<const details::key_template_literal_segment&>(*segment);

			for (const char c : literal.text) {
				/*
				 * Escape `{` as `{{` and `}` as `}}` so the output
				 * round-trips through
				 * `lttng_key_template_create_from_string()`.
				 */
				if (c == '{' || c == '}') {
					out.push_back(c);
				}

				out.push_back(c);
			}

			break;
		}
		case details::key_template_segment_type::EVENT_NAME:
		case details::key_template_segment_type::PROVIDER_NAME:
			out += fmt::format("{{{}}}", placeholder_name(segment->type));
			break;
		}
	}

	return out;
}

int serialize_cstr(const char *str, struct lttng_dynamic_buffer *buf)
{
	const uint32_t len = strlen(str) + 1;
	int ret;

	ret = lttng_dynamic_buffer_append(buf, &len, sizeof(len));
	if (ret) {
		return ret;
	}

	return lttng_dynamic_buffer_append(buf, str, len);
}

int serialize_segment(const details::key_template_segment& segment, struct lttng_payload *payload)
{
	const uint8_t type = static_cast<uint8_t>(segment.type);
	int ret;

	ret = lttng_dynamic_buffer_append(&payload->buffer, &type, sizeof(type));
	if (ret) {
		return ret;
	}

	switch (segment.type) {
	case details::key_template_segment_type::LITERAL:
	{
		const auto& literal =
			static_cast<const details::key_template_literal_segment&>(segment);

		return serialize_cstr(literal.text.c_str(), &payload->buffer);
	}
	case details::key_template_segment_type::EVENT_NAME:
	case details::key_template_segment_type::PROVIDER_NAME:
		/* Type byte is sufficient. */
		return 0;
	}

	std::abort();
}

/*
 * Deserializes a single segment from the start of `view`.
 *
 * On success, returns the number of bytes consumed and sets `out_segment`; on
 * failure, returns a negative value.
 */
ssize_t deserialize_segment(const struct lttng_buffer_view *view,
			    std::unique_ptr<details::key_template_segment>& out_segment)
{
	const struct lttng_buffer_view type_view =
		lttng_buffer_view_from_view(view, 0, sizeof(uint8_t));

	if (!lttng_buffer_view_is_valid(&type_view)) {
		return -1;
	}

	const auto type =
		static_cast<details::key_template_segment_type>((unsigned char) *type_view.data);
	ssize_t consumed_len = sizeof(uint8_t);

	switch (type) {
	case details::key_template_segment_type::LITERAL:
	{
		const struct lttng_buffer_view len_view =
			lttng_buffer_view_from_view(view, consumed_len, sizeof(uint32_t));

		if (!lttng_buffer_view_is_valid(&len_view)) {
			return -1;
		}

		uint32_t text_len;

		memcpy(&text_len, len_view.data, sizeof(text_len));
		consumed_len += sizeof(text_len);

		const char *const text = &view->data[consumed_len];

		if (!lttng_buffer_view_contains_string(view, text, text_len)) {
			return -1;
		}

		if (text[0] == '\0') {
			return -1;
		}

		out_segment = lttng::make_unique<details::key_template_literal_segment>(
			std::string(text));
		consumed_len += text_len;
		return consumed_len;
	}
	case details::key_template_segment_type::EVENT_NAME:
		out_segment = lttng::make_unique<details::key_template_placeholder_segment>(
			details::key_template_segment_type::EVENT_NAME);
		return consumed_len;
	case details::key_template_segment_type::PROVIDER_NAME:
		out_segment = lttng::make_unique<details::key_template_placeholder_segment>(
			details::key_template_segment_type::PROVIDER_NAME);
		return consumed_len;
	}

	ERR_FMT("Invalid key template segment type encountered while deserializing: type={}",
		static_cast<unsigned int>((unsigned char) *type_view.data));
	return -1;
}
} /* namespace */

struct lttng_key_template *lttng_key_template_create_from_string(const char *str)
{
	try {
		if (!str || *str == '\0') {
			return nullptr;
		}

		return parse_template_string(str).release();
	} catch (const std::exception& e) {
		ERR_FMT("Failed to create key template from string: {}", e.what());
		return nullptr;
	}
}

enum lttng_key_template_status lttng_key_template_to_string(const struct lttng_key_template *tmpl,
							    char **str)
{
	if (!tmpl || !str) {
		return LTTNG_KEY_TEMPLATE_STATUS_INVALID;
	}

	try {
		const std::string rendered = render_template(*tmpl);
		char *const out = strdup(rendered.c_str());

		if (!out) {
			return LTTNG_KEY_TEMPLATE_STATUS_ERROR;
		}

		*str = out;
		return LTTNG_KEY_TEMPLATE_STATUS_OK;
	} catch (const std::exception& e) {
		ERR_FMT("Failed to render key template to string: {}", e.what());
		return LTTNG_KEY_TEMPLATE_STATUS_ERROR;
	}
}

void lttng_key_template_destroy(struct lttng_key_template *tmpl)
{
	delete tmpl;
}

lttng_key_template::lttng_key_template(const lttng_key_template& other)
{
	segments.reserve(other.segments.size());

	for (const auto& segment : other.segments) {
		segments.emplace_back(segment->clone());
	}
}

bool lttng_key_template::operator==(const lttng_key_template& other) const noexcept
{
	if (segments.size() != other.segments.size()) {
		return false;
	}

	for (std::size_t i = 0; i < segments.size(); ++i) {
		if (!segments[i]->equals(*other.segments[i])) {
			return false;
		}
	}

	return true;
}

int lttng_key_template::serialize(lttng_payload& payload) const
{
	template_comm comm;

	comm.segment_count = static_cast<uint32_t>(segments.size());

	if (lttng_dynamic_buffer_append(&payload.buffer, &comm, sizeof(comm))) {
		return -1;
	}

	for (const auto& segment : segments) {
		if (serialize_segment(*segment, &payload)) {
			return -1;
		}
	}

	return 0;
}

ssize_t lttng_key_template::create_from_payload(lttng_payload_view& view,
						std::unique_ptr<lttng_key_template>& out_tmpl)
{
	const struct lttng_buffer_view comm_view =
		lttng_buffer_view_from_view(&view.buffer, 0, sizeof(template_comm));

	if (!lttng_buffer_view_is_valid(&comm_view)) {
		return -1;
	}

	template_comm comm;

	memcpy(&comm, comm_view.data, sizeof(comm));

	ssize_t consumed_len = sizeof(comm);
	auto tmpl = lttng::make_unique<lttng_key_template>();

	tmpl->segments.reserve(comm.segment_count);

	for (uint32_t i = 0; i < comm.segment_count; ++i) {
		const struct lttng_buffer_view segment_view =
			lttng_buffer_view_from_view(&view.buffer, consumed_len, -1);
		std::unique_ptr<details::key_template_segment> segment;

		const ssize_t segment_consumed_len = deserialize_segment(&segment_view, segment);

		if (segment_consumed_len < 0) {
			return -1;
		}

		tmpl->segments.emplace_back(std::move(segment));
		consumed_len += segment_consumed_len;
	}

	out_tmpl = std::move(tmpl);
	return consumed_len;
}
