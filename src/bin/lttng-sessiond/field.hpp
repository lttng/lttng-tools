/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_FIELD_H
#define LTTNG_FIELD_H

#include <memory>
#include <string>
#include <type_traits>
#include <vector>

#include <vendor/optional.hpp>

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
	virtual void accept(type_visitor& visitor) const = 0;

	const unsigned int alignment;

protected:
	type(unsigned int alignment);

private:
	virtual bool _is_equal(const type& rhs) const noexcept = 0;
};

class field {
public:
	using cuptr = std::unique_ptr<const field>;

	field(std::string name, type::cuptr type);
	void accept(field_visitor& visitor) const;
	bool operator==(const field& other) const noexcept;

	const std::string name;
	const type::cuptr _type;
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

	virtual void accept(type_visitor& visitor) const override;

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
	virtual bool _is_equal(const type& other) const noexcept override;
};

class floating_point_type : public type {
public:
	floating_point_type(unsigned int alignment,
			byte_order byte_order,
			unsigned int exponent_digits,
			unsigned int mantissa_digits);

	virtual void accept(type_visitor& visitor) const override final;

	const enum byte_order byte_order;
	const unsigned int exponent_digits;
	const unsigned int mantissa_digits;

private:
	virtual bool _is_equal(const type& other) const noexcept override final;
};

class enumeration_type : public integer_type {
protected:
	enumeration_type(unsigned int alignment,
			enum byte_order byte_order,
			unsigned int size,
			enum signedness signedness,
			enum base base,
			integer_type::roles roles = {});

	virtual void accept(type_visitor& visitor) const = 0;
};

namespace details {
template <class MappingIntegerType>
class enumeration_mapping_range {
public:
	using range_integer_t = MappingIntegerType;

	enumeration_mapping_range(MappingIntegerType in_begin, MappingIntegerType in_end) :
		begin{in_begin}, end{in_end}
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

	enumeration_mapping(const enumeration_mapping<MappingIntegerType>& other) = delete;
	enumeration_mapping(const enumeration_mapping<MappingIntegerType>&& other) :
		name{std::move(other.name)}, range{other.range}
	{
	}

	/* Mapping with an implicit value. */
	enumeration_mapping(std::string in_name) : name{std::move(in_name)}
	{
	}

	enumeration_mapping(std::string in_name, range_t in_range) : name{std::move(in_name)}, range{in_range}
	{
	}

	const std::string name;
	const nonstd::optional<range_t> range;
};

template <class MappingIntegerType>
bool operator==(const enumeration_mapping<MappingIntegerType>& lhs,
		const enumeration_mapping<MappingIntegerType>& rhs) noexcept
{
	return lhs.name == rhs.name && lhs.range == rhs.range;
}
} /* namespace details */

template <class MappingIntegerType>
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
		_mappings{std::move(in_mappings)}
	{
	}

	virtual void accept(type_visitor& visitor) const override final;

	const std::shared_ptr<const mappings> _mappings;

private:
	virtual bool _is_equal(const type& base_other) const noexcept override final
	{
		const auto& other = static_cast<const typed_enumeration_type<MappingIntegerType>&>(
				base_other);

		return integer_type::_is_equal(base_other) && *this->_mappings == *other._mappings;
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
	virtual bool _is_equal(const type& base_other) const noexcept override;
};

class static_length_array_type : public array_type {
public:
	static_length_array_type(unsigned int alignment,
			type::cuptr element_type,
			uint64_t in_length);

	virtual void accept(type_visitor& visitor) const override final;

	const uint64_t length;

private:
	virtual bool _is_equal(const type& base_other) const noexcept override final;
};

class dynamic_length_array_type : public array_type {
public:
	dynamic_length_array_type(unsigned int alignment,
			type::cuptr element_type,
			field_location length_field_location);

	virtual void accept(type_visitor& visitor) const override final;

	const field_location length_field_location;

private:
	virtual bool _is_equal(const type& base_other) const noexcept override final;
};

class static_length_blob_type : public type {
public:
	enum class role {
		/* Packet header field class specific role. */
		TRACE_CLASS_UUID,
	};

	using roles = std::vector<role>;

	static_length_blob_type(unsigned int alignment, uint64_t in_length_bytes, roles roles = {});

	virtual void accept(type_visitor& visitor) const override final;

	const uint64_t length_bytes;
	const roles roles_;

private:
	virtual bool _is_equal(const type& base_other) const noexcept override final;
};

class dynamic_length_blob_type : public type {
public:
	dynamic_length_blob_type(unsigned int alignment, field_location length_field_location);

	virtual void accept(type_visitor& visitor) const override final;

	const field_location length_field_location;

private:
	virtual bool _is_equal(const type& base_other) const noexcept override final;
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
	virtual bool _is_equal(const type& base_other) const noexcept override;
};

class static_length_string_type : public string_type {
public:
	static_length_string_type(
			unsigned int alignment, enum encoding in_encoding, uint64_t length);
	virtual void accept(type_visitor& visitor) const override final;

	const uint64_t length;

private:
	virtual bool _is_equal(const type& base_other) const noexcept override final;
};

class dynamic_length_string_type : public string_type {
public:
	dynamic_length_string_type(unsigned int alignment,
			enum encoding in_encoding,
			field_location length_field_location);
	virtual void accept(type_visitor& visitor) const override final;

	const field_location length_field_location;

private:
	virtual bool _is_equal(const type& base_other) const noexcept override final;
};

class null_terminated_string_type : public string_type {
public:
	null_terminated_string_type(unsigned int alignment, enum encoding in_encoding);
	virtual void accept(type_visitor& visitor) const override final;
};

class structure_type : public type {
public:
	using fields = std::vector<field::cuptr>;

	structure_type(unsigned int alignment, fields in_fields);

	virtual void accept(type_visitor& visitor) const override final;

	const fields _fields;

private:
	virtual bool _is_equal(const type& base_other) const noexcept override final;
};

class variant_type : public type {
public:
	using choices = std::vector<field::cuptr>;

	variant_type(unsigned int alignment,
			field_location selector_field_location,
			choices in_choices);

	virtual void accept(type_visitor& visitor) const override final;

	const field_location selector_field_location;
	const choices _choices;
;

private:
	virtual bool _is_equal(const type& base_other) const noexcept override final;
};

class field_visitor {
public:
	virtual ~field_visitor() = default;
	virtual void visit(const field& field) = 0;

protected:
	field_visitor() = default;
};

class type_visitor {
public:
	virtual ~type_visitor() = default;
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
	virtual void visit(const variant_type& type) = 0;

protected:
	type_visitor() = default;
};

} /* namespace trace */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_FIELD_H */
