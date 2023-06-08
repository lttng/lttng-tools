/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_FIELD_H
#define LTTNG_FIELD_H

#include <common/format.hpp>
#include <common/make-unique.hpp>

#include <vendor/optional.hpp>

#include <algorithm>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

namespace lttng {
namespace sessiond {
namespace trace {

class field_visitor;
class type_visitor;

enum class byte_order {
	BIG_ENDIAN_,
	LITTLE_ENDIAN_,
};

class field_location {
public:
	enum class root {
		PACKET_HEADER,
		PACKET_CONTEXT,
		EVENT_RECORD_HEADER,
		EVENT_RECORD_COMMON_CONTEXT,
		EVENT_RECORD_SPECIFIC_CONTEXT,
		EVENT_RECORD_PAYLOAD,
	};

	using elements = std::vector<std::string>;

	field_location(root lookup_root, elements elements);
	bool operator==(const field_location& other) const noexcept;

	const root root_;
	const elements elements_;
};

/*
 * Field, and the various field types, represents fields as exposed by the
 * LTTng tracers. These classes do not attempt to describe the complete spectrum of the CTF
 * specification.
 */

class type {
public:
	using cuptr = std::unique_ptr<const type>;

	static byte_order reverse_byte_order(byte_order byte_order) noexcept;

	bool operator==(const type& other) const noexcept;
	bool operator!=(const type& other) const noexcept;

	virtual ~type();
	type(const type&) = delete;
	type(type&&) = delete;
	type& operator=(type&&) = delete;
	type& operator=(const type&) = delete;

	/* Obtain an independent copy of `type`. */
	virtual type::cuptr copy() const = 0;

	virtual void accept(type_visitor& visitor) const = 0;

	const unsigned int alignment;

protected:
	explicit type(unsigned int alignment);

private:
	virtual bool _is_equal(const type& rhs) const noexcept = 0;
};

class field {
public:
	using uptr = std::unique_ptr<field>;
	using cuptr = std::unique_ptr<const field>;

	field(std::string name, type::cuptr type);
	void accept(field_visitor& visitor) const;
	bool operator==(const field& other) const noexcept;

	const type& get_type() const;
	type::cuptr move_type() noexcept;

	const std::string name;

private:
	type::cuptr _type;
};

class integer_type : public type {
public:
	enum class signedness {
		SIGNED,
		UNSIGNED,
	};

	enum class base {
		BINARY = 2,
		OCTAL = 8,
		DECIMAL = 10,
		HEXADECIMAL = 16,
	};

	enum class role {
		DEFAULT_CLOCK_TIMESTAMP,
		/* Packet header field class specific roles. */
		DATA_STREAM_CLASS_ID,
		DATA_STREAM_ID,
		PACKET_MAGIC_NUMBER,
		/* Packet context field class specific roles. */
		DISCARDED_EVENT_RECORD_COUNTER_SNAPSHOT,
		PACKET_CONTENT_LENGTH,
		PACKET_END_DEFAULT_CLOCK_TIMESTAMP,
		PACKET_SEQUENCE_NUMBER,
		PACKET_TOTAL_LENGTH,
		/* Event record field class roles. */
		EVENT_RECORD_CLASS_ID,
	};

	using roles = std::vector<role>;

	integer_type(unsigned int alignment,
		     byte_order byte_order,
		     unsigned int size,
		     signedness signedness,
		     base base,
		     roles roles = {});

	type::cuptr copy() const override;

	void accept(type_visitor& visitor) const override;

	const enum byte_order byte_order;
	const unsigned int size;
	/*
	 * signedness and base are suffixed with '_' to work-around a bug in older
	 * GCCs (before 6) that do not recognize hidden/shadowed enumeration as valid
	 * nested-name-specifiers.
	 */
	const signedness signedness_;
	const base base_;
	const roles roles_;

protected:
	bool _is_equal(const type& other) const noexcept override;
};

class floating_point_type : public type {
public:
	floating_point_type(unsigned int alignment,
			    byte_order byte_order,
			    unsigned int exponent_digits,
			    unsigned int mantissa_digits);

	type::cuptr copy() const final;

	void accept(type_visitor& visitor) const final;

	const enum byte_order byte_order;
	const unsigned int exponent_digits;
	const unsigned int mantissa_digits;

private:
	bool _is_equal(const type& other) const noexcept final;
};

class enumeration_type : public integer_type {
public:
	~enumeration_type() override = default;
	enumeration_type(const enumeration_type&) = delete;
	enumeration_type(enumeration_type&&) = delete;
	enumeration_type& operator=(enumeration_type&&) = delete;
	enumeration_type& operator=(const enumeration_type&) = delete;

protected:
	enumeration_type(unsigned int alignment,
			 enum byte_order byte_order,
			 unsigned int size,
			 enum signedness signedness,
			 enum base base,
			 integer_type::roles roles = {});

	void accept(type_visitor& visitor) const override = 0;
};

namespace details {
template <class MappingIntegerType>
class enumeration_mapping_range {
public:
	using range_integer_t = MappingIntegerType;

	enumeration_mapping_range(MappingIntegerType in_begin, MappingIntegerType in_end) :
		begin{ in_begin }, end{ in_end }
	{
	}

	const range_integer_t begin, end;
};

template <class MappingIntegerType>
bool operator==(const enumeration_mapping_range<MappingIntegerType>& lhs,
		const enumeration_mapping_range<MappingIntegerType>& rhs) noexcept
{
	return lhs.begin == rhs.begin && lhs.end == rhs.end;
}

template <class MappingIntegerType>
class enumeration_mapping {
public:
	using range_t = enumeration_mapping_range<MappingIntegerType>;

	enumeration_mapping(std::string in_name, MappingIntegerType value) :
		name{ std::move(in_name) }, range{ value, value }
	{
	}

	enumeration_mapping(std::string in_name, range_t in_range) :
		name{ std::move(in_name) }, range{ in_range }
	{
	}

	enumeration_mapping(const enumeration_mapping<MappingIntegerType>& other) = default;
	enumeration_mapping(enumeration_mapping<MappingIntegerType>&& other) noexcept :
		name{ std::move(other.name) }, range{ other.range }
	{
	}

	enumeration_mapping& operator=(enumeration_mapping&&) = delete;
	enumeration_mapping& operator=(const enumeration_mapping&) = delete;
	~enumeration_mapping() = default;

	const std::string name;
	/*
	 * Only one range per mapping is supported for the moment as
	 * the tracers (and CTF 1.8) can't express multiple ranges per
	 * mapping, which is allowed by CTF 2.
	 */
	const range_t range;
};

template <class MappingIntegerType>
bool operator==(const enumeration_mapping<MappingIntegerType>& lhs,
		const enumeration_mapping<MappingIntegerType>& rhs) noexcept
{
	return lhs.name == rhs.name && lhs.range == rhs.range;
}
} /* namespace details */

template <typename MappingIntegerType>
class typed_enumeration_type : public enumeration_type {
public:
	using mapping = details::enumeration_mapping<MappingIntegerType>;
	using mappings = std::vector<mapping>;

	static_assert(std::is_integral<MappingIntegerType>::value &&
			      sizeof(MappingIntegerType) == 8,
		      "MappingIntegerType must be either int64_t or uint64_t");

	typed_enumeration_type(unsigned int in_alignment,
			       enum byte_order in_byte_order,
			       unsigned int in_size,
			       enum base in_base,
			       const std::shared_ptr<const mappings>& in_mappings,
			       integer_type::roles in_roles = {}) :
		enumeration_type(in_alignment,
				 in_byte_order,
				 in_size,
				 std::is_signed<MappingIntegerType>::value ?
					 integer_type::signedness::SIGNED :
					 integer_type::signedness::UNSIGNED,
				 in_base,
				 std::move(in_roles)),
		mappings_{ std::move(in_mappings) }
	{
	}

	type::cuptr copy() const override
	{
		return lttng::make_unique<typed_enumeration_type<MappingIntegerType>>(
			alignment, byte_order, size, base_, mappings_, roles_);
	}

	void accept(type_visitor& visitor) const final;

	const std::shared_ptr<const mappings> mappings_;

private:
	bool _is_equal(const type& base_other) const noexcept final
	{
		const auto& other =
			static_cast<const typed_enumeration_type<MappingIntegerType>&>(base_other);

		return integer_type::_is_equal(base_other) && *this->mappings_ == *other.mappings_;
	}
};

/* Aliases for all allowed enumeration mapping types. */
using signed_enumeration_type = typed_enumeration_type<int64_t>;
using unsigned_enumeration_type = typed_enumeration_type<uint64_t>;

class array_type : public type {
public:
	array_type(unsigned int alignment, type::cuptr element_type);

	const type::cuptr element_type;

protected:
	bool _is_equal(const type& base_other) const noexcept override;
};

class static_length_array_type : public array_type {
public:
	static_length_array_type(unsigned int alignment,
				 type::cuptr element_type,
				 uint64_t in_length);

	type::cuptr copy() const final;

	void accept(type_visitor& visitor) const final;

	const uint64_t length;

private:
	bool _is_equal(const type& base_other) const noexcept final;
};

class dynamic_length_array_type : public array_type {
public:
	dynamic_length_array_type(unsigned int alignment,
				  type::cuptr element_type,
				  field_location length_field_location);

	type::cuptr copy() const final;

	void accept(type_visitor& visitor) const final;

	const field_location length_field_location;

private:
	bool _is_equal(const type& base_other) const noexcept final;
};

class static_length_blob_type : public type {
public:
	enum class role {
		/* Packet header field class specific role. */
		METADATA_STREAM_UUID,
	};

	using roles = std::vector<role>;

	static_length_blob_type(unsigned int alignment, uint64_t in_length_bytes, roles roles = {});

	type::cuptr copy() const final;

	void accept(type_visitor& visitor) const final;

	const uint64_t length_bytes;
	const roles roles_;

private:
	bool _is_equal(const type& base_other) const noexcept final;
};

class dynamic_length_blob_type : public type {
public:
	dynamic_length_blob_type(unsigned int alignment, field_location length_field_location);

	type::cuptr copy() const final;

	void accept(type_visitor& visitor) const final;

	const field_location length_field_location;

private:
	bool _is_equal(const type& base_other) const noexcept final;
};

class string_type : public type {
public:
	enum class encoding {
		ASCII,
		UTF8,
	};

	string_type(unsigned int alignment, enum encoding encoding);

	/*
	 * encoding is suffixed with '_' to work-around a bug in older
	 * GCCs (before 6) that do not recognize hidden/shadowed enumeration as valid
	 * nested-name-specifiers.
	 */
	const encoding encoding_;

protected:
	bool _is_equal(const type& base_other) const noexcept override;
};

class static_length_string_type : public string_type {
public:
	static_length_string_type(unsigned int alignment,
				  enum encoding in_encoding,
				  uint64_t length);

	type::cuptr copy() const final;

	void accept(type_visitor& visitor) const final;

	const uint64_t length;

private:
	bool _is_equal(const type& base_other) const noexcept final;
};

class dynamic_length_string_type : public string_type {
public:
	dynamic_length_string_type(unsigned int alignment,
				   enum encoding in_encoding,
				   field_location length_field_location);

	type::cuptr copy() const final;

	void accept(type_visitor& visitor) const final;

	const field_location length_field_location;

private:
	bool _is_equal(const type& base_other) const noexcept final;
};

class null_terminated_string_type : public string_type {
public:
	null_terminated_string_type(unsigned int alignment, enum encoding in_encoding);

	type::cuptr copy() const final;

	void accept(type_visitor& visitor) const final;
};

class structure_type : public type {
public:
	using fields = std::vector<field::cuptr>;

	structure_type(unsigned int alignment, fields in_fields);

	type::cuptr copy() const final;

	void accept(type_visitor& visitor) const final;

	const fields fields_;

private:
	bool _is_equal(const type& base_other) const noexcept final;
};

template <typename MappingIntegerType>
class variant_type : public type {
	static_assert(
		std::is_same<MappingIntegerType,
			     unsigned_enumeration_type::mapping::range_t::range_integer_t>::value ||
			std::is_same<
				MappingIntegerType,
				signed_enumeration_type::mapping::range_t::range_integer_t>::value,
		"Variant mapping integer type must be one of those allowed by typed_enumeration_type");

public:
	using choice =
		std::pair<const details::enumeration_mapping<MappingIntegerType>, type::cuptr>;
	using choices = std::vector<choice>;

	variant_type(unsigned int in_alignment,
		     field_location in_selector_field_location,
		     choices in_choices) :
		type(in_alignment),
		selector_field_location{ std::move(in_selector_field_location) },
		choices_{ std::move(in_choices) }
	{
	}

	type::cuptr copy() const final
	{
		choices copy_of_choices;

		copy_of_choices.reserve(choices_.size());
		for (const auto& current_choice : choices_) {
			copy_of_choices.emplace_back(current_choice.first,
						     current_choice.second->copy());
		}

		return lttng::make_unique<variant_type<MappingIntegerType>>(
			alignment, selector_field_location, std::move(copy_of_choices));
	}

	void accept(type_visitor& visitor) const final;

	const field_location selector_field_location;
	const choices choices_;

private:
	static bool _choices_are_equal(const choices& a, const choices& b)
	{
		if (a.size() != b.size()) {
			return false;
		}

		return std::equal(a.cbegin(),
				  a.cend(),
				  b.cbegin(),
				  [](const choice& choice_a, const choice& choice_b) {
					  return choice_a.first == choice_b.first &&
						  *choice_a.second == *choice_b.second;
				  });
	}

	bool _is_equal(const type& base_other) const noexcept final
	{
		const auto& other = static_cast<decltype(*this)&>(base_other);

		return selector_field_location == other.selector_field_location &&
			_choices_are_equal(choices_, other.choices_);
	}
};

class field_visitor {
public:
	virtual ~field_visitor() = default;
	field_visitor(field_visitor&&) = delete;
	field_visitor(const field_visitor&) = delete;
	field_visitor& operator=(const field_visitor&) = delete;
	field_visitor& operator=(field_visitor&&) = delete;

	virtual void visit(const field& field) = 0;

protected:
	field_visitor() = default;
};

class type_visitor {
public:
	virtual ~type_visitor() = default;
	type_visitor(type_visitor&&) = delete;
	type_visitor(const type_visitor&) = delete;
	type_visitor& operator=(const type_visitor&) = delete;
	type_visitor& operator=(type_visitor&&) = delete;

	virtual void visit(const integer_type& type) = 0;
	virtual void visit(const floating_point_type& type) = 0;
	virtual void visit(const signed_enumeration_type& type) = 0;
	virtual void visit(const unsigned_enumeration_type& type) = 0;
	virtual void visit(const static_length_array_type& type) = 0;
	virtual void visit(const dynamic_length_array_type& type) = 0;
	virtual void visit(const static_length_blob_type& type) = 0;
	virtual void visit(const dynamic_length_blob_type& type) = 0;
	virtual void visit(const null_terminated_string_type& type) = 0;
	virtual void visit(const static_length_string_type& type) = 0;
	virtual void visit(const dynamic_length_string_type& type) = 0;
	virtual void visit(const structure_type& type) = 0;
	virtual void
	visit(const variant_type<signed_enumeration_type::mapping::range_t::range_integer_t>&
		      type) = 0;
	virtual void
	visit(const variant_type<unsigned_enumeration_type::mapping::range_t::range_integer_t>&
		      type) = 0;

protected:
	type_visitor() = default;
};

} /* namespace trace */
} /* namespace sessiond */
} /* namespace lttng */

/*
 * Field formatters for libfmt.
 *
 * Due to a bug in g++ < 7.1, this specialization must be enclosed in the fmt namespace,
 * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56480.
 */
namespace fmt {
template <>
struct formatter<lttng::sessiond::trace::field_location> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator
	format(const lttng::sessiond::trace::field_location& location, FormatContextType& ctx)
	{
		std::string location_str{ "[" };

		switch (location.root_) {
		case lttng::sessiond::trace::field_location::root::PACKET_HEADER:
			location_str += "\"packet-header\"";
			break;
		case lttng::sessiond::trace::field_location::root::PACKET_CONTEXT:
			location_str += "\"packet-context\"";
			break;
		case lttng::sessiond::trace::field_location::root::EVENT_RECORD_HEADER:
			location_str += "\"event-record-header\"";
			break;
		case lttng::sessiond::trace::field_location::root::EVENT_RECORD_COMMON_CONTEXT:
			location_str += "\"event-record-common-context\"";
			break;
		case lttng::sessiond::trace::field_location::root::EVENT_RECORD_SPECIFIC_CONTEXT:
			location_str += "\"event-record-specific-context\"";
			break;
		case lttng::sessiond::trace::field_location::root::EVENT_RECORD_PAYLOAD:
			location_str += "\"event-record-payload\"";
			break;
		}

		for (const auto& name : location.elements_) {
			location_str += ", \"" + name + "\"";
		}

		location_str += "]";
		return format_to(ctx.out(), location_str);
	}
};

namespace details {
template <typename MappingIntegerType>
::std::string format_mapping_range(typename lttng::sessiond::trace::typed_enumeration_type<
				   MappingIntegerType>::mapping::range_t range)
{
	if (range.begin == range.end) {
		return ::lttng::format("[{}]", range.begin);
	} else {
		return ::lttng::format("[{}, {}]", range.begin, range.end);
	}
}
} /* namespace details */

template <>
struct formatter<typename lttng::sessiond::trace::signed_enumeration_type::mapping::range_t>
	: formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator
	format(typename lttng::sessiond::trace::signed_enumeration_type::mapping::range_t range,
	       FormatContextType& ctx)
	{
		return format_to(ctx.out(),
				 details::format_mapping_range<
					 lttng::sessiond::trace::signed_enumeration_type::mapping::
						 range_t::range_integer_t>(range));
	}
};

template <>
struct formatter<typename lttng::sessiond::trace::unsigned_enumeration_type::mapping::range_t>
	: formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator
	format(typename lttng::sessiond::trace::unsigned_enumeration_type::mapping::range_t range,
	       FormatContextType& ctx)
	{
		return format_to(ctx.out(),
				 details::format_mapping_range<
					 lttng::sessiond::trace::unsigned_enumeration_type::
						 mapping::range_t::range_integer_t>(range));
	}
};

} /* namespace fmt */

#endif /* LTTNG_FIELD_H */
