/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_KEY_TEMPLATE_INTERNAL_H
#define LTTNG_ACTION_KEY_TEMPLATE_INTERNAL_H

#include <common/macros.hpp>
#include <common/make-unique.hpp>

#include <lttng/action/key-template.h>

#include <memory>
#include <string>
#include <sys/types.h>
#include <vector>

struct lttng_payload;
struct lttng_payload_view;

namespace lttng {
namespace action {
namespace details {

enum class key_template_segment_type {
	LITERAL = 0,
	EVENT_NAME = 1,
	PROVIDER_NAME = 2,
};

class key_template_segment {
public:
	explicit key_template_segment(key_template_segment_type segment_type) noexcept :
		type(segment_type)
	{
	}

	virtual ~key_template_segment() = default;

	key_template_segment(const key_template_segment&) = delete;
	key_template_segment& operator=(const key_template_segment&) = delete;
	key_template_segment(key_template_segment&&) = delete;
	key_template_segment& operator=(key_template_segment&&) = delete;

	virtual std::unique_ptr<key_template_segment> clone() const = 0;
	virtual bool equals(const key_template_segment& other) const noexcept = 0;

	const key_template_segment_type type;
};

class key_template_literal_segment final : public key_template_segment {
public:
	explicit key_template_literal_segment(std::string literal_text) :
		key_template_segment(key_template_segment_type::LITERAL),
		text(std::move(literal_text))
	{
	}

	std::unique_ptr<key_template_segment> clone() const override
	{
		return lttng::make_unique<key_template_literal_segment>(text);
	}

	bool equals(const key_template_segment& other) const noexcept override
	{
		if (other.type != key_template_segment_type::LITERAL) {
			return false;
		}

		return text == static_cast<const key_template_literal_segment&>(other).text;
	}

	const std::string text;
};

class key_template_placeholder_segment final : public key_template_segment {
public:
	explicit key_template_placeholder_segment(key_template_segment_type placeholder_type) :
		key_template_segment(placeholder_type)
	{
		LTTNG_ASSERT(placeholder_type == key_template_segment_type::EVENT_NAME ||
			     placeholder_type == key_template_segment_type::PROVIDER_NAME);
	}

	std::unique_ptr<key_template_segment> clone() const override
	{
		return lttng::make_unique<key_template_placeholder_segment>(type);
	}

	bool equals(const key_template_segment& other) const noexcept override
	{
		return other.type == type;
	}
};

} /* namespace details */
} /* namespace action */
} /* namespace lttng */

/*
 * A key template is a list of segments where each segment is either a
 * verbatim string or a placeholder that the tracer interpolates against
 * the matching event.
 */
struct lttng_key_template {
	lttng_key_template() = default;

	/*
	 * Builds a deep copy of `other`.
	 */
	lttng_key_template(const lttng_key_template& other);

	lttng_key_template& operator=(const lttng_key_template&) = delete;
	lttng_key_template(lttng_key_template&&) noexcept = default;
	lttng_key_template& operator=(lttng_key_template&&) noexcept = default;
	~lttng_key_template() = default;

	/*
	 * Creates a key template from the start of `view`.
	 *
	 * On success, returns the number of bytes consumed from `view` and sets
	 * `out_tmpl` to the new key template; on failure, returns a negative
	 * value (and leaves `out_tmpl` unchanged).
	 */
	static ssize_t create_from_payload(lttng_payload_view& view,
					   std::unique_ptr<lttng_key_template>& out_tmpl);

	/*
	 * Two key templates are equal when their segment lists have the same
	 * length and each pair of segments at matching positions have the same
	 * type and (for literal segments) the same verbatim text.
	 */
	bool operator==(const lttng_key_template& other) const noexcept;
	bool operator!=(const lttng_key_template& other) const noexcept
	{
		return !(*this == other);
	}

	/*
	 * Serializes this template into `payload`.
	 *
	 * Returns 0 on success, -1 on failure.
	 */
	int serialize(lttng_payload& payload) const;

	std::vector<std::unique_ptr<lttng::action::details::key_template_segment>> segments;
};

#endif /* LTTNG_ACTION_KEY_TEMPLATE_INTERNAL_H */
