/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "field.hpp"

#include <common/exception.hpp>
#include <common/format.hpp>

namespace lst = lttng::sessiond::trace;

namespace {
template <class FieldTypeSet>
bool fields_are_equal(const FieldTypeSet& a, const FieldTypeSet& b)
{
	if (a.size() != b.size()) {
		return false;
	}

	return std::equal(a.cbegin(), a.cend(), b.cbegin(),
			[](typename FieldTypeSet::const_reference field_a,
					typename FieldTypeSet::const_reference field_b) {
				return *field_a == *field_b;
			});
}
} /* namespace */

lst::type::type(unsigned int in_alignment) : alignment{in_alignment}
{
}

lst::type::~type()
{
}

bool lst::type::operator==(const lst::type& other) const noexcept
{
	return typeid(*this) == typeid(other) &&
		alignment == other.alignment &&
		/* defer to concrete type comparison */
		this->_is_equal(other);
}

bool lst::type::operator!=(const lst::type& other) const noexcept
{
	return !(*this == other);
}

lst::field::field(std::string in_name, lst::type::cuptr in_type) :
	name{std::move(in_name)}, _type{std::move(in_type)}
{
}

void lst::field::accept(lst::field_visitor& visitor) const
{
	visitor.visit(*this);
}

bool lst::field::operator==(const lst::field& other) const noexcept
{
	return name == other.name && *_type == *other._type;
}

lst::integer_type::integer_type(unsigned int in_alignment,
		enum lst::byte_order in_byte_order,
		unsigned int in_size,
		enum lst::integer_type::signedness in_signedness,
		enum lst::integer_type::base in_base) :
	type(in_alignment),
	byte_order{in_byte_order},
	size{in_size},
	signedness{in_signedness},
	base{in_base}
{
}

bool lst::integer_type::_is_equal(const type &base_other) const noexcept
{
	const auto& other = static_cast<decltype(*this)&>(base_other);

	return this->byte_order == other.byte_order &&
		this->size == other.size &&
		this->signedness == other.signedness &&
		this->base == other.base;
}

void lst::integer_type::accept(type_visitor& visitor) const
{
	visitor.visit(*this);
}

lst::byte_order lst::type::reverse_byte_order(lst::byte_order byte_order) noexcept
{
	if (byte_order == lst::byte_order::BIG_ENDIAN_) {
		return lst::byte_order::LITTLE_ENDIAN_;
	} else {
		return lst::byte_order::BIG_ENDIAN_;
	}
}

lst::floating_point_type::floating_point_type(unsigned int in_alignment,
		lst::byte_order in_byte_order,
		unsigned int in_exponent_digits,
		unsigned int in_mantissa_digits) :
	type(in_alignment),
	byte_order(in_byte_order),
	exponent_digits{in_exponent_digits},
	mantissa_digits(in_mantissa_digits)
{
	/* Allowed (exponent, mantissa) pairs. */
	static const std::vector<std::pair<unsigned int, unsigned int>> allowed_pairs{
			{5, 11}, /* binary16 */
			{8, 24}, /* binary32 */
			{11, 53}, /* binary64 */
			{15, 113}, /* binary128 */
	};

	const auto input_pair = decltype(allowed_pairs)::value_type(exponent_digits, mantissa_digits);
	for (const auto& pair : allowed_pairs) {
		if (input_pair == pair) {
			/* mantissa and exponent digits is a valid pair. */
			return;
		}
	}

	LTTNG_THROW_INVALID_ARGUMENT_ERROR(
			fmt::format("Invalid exponent/mantissa values provided while creating {}",
					typeid(*this)));
}

void lst::floating_point_type::accept(type_visitor& visitor) const
{
	visitor.visit(*this);
}

bool lst::floating_point_type::_is_equal(const type& base_other) const noexcept
{
	const auto& other = static_cast<decltype(*this)&>(base_other);

	return this->byte_order == other.byte_order &&
			this->exponent_digits == other.exponent_digits &&
			this->mantissa_digits == other.mantissa_digits;
}

lst::enumeration_type::enumeration_type(unsigned int in_alignment,
		enum lst::byte_order in_byte_order,
		unsigned int in_size,
		enum signedness in_signedness,
		enum base in_base) :
	integer_type(in_alignment, in_byte_order, in_size, in_signedness, in_base)
{
}

template <>
void lst::signed_enumeration_type::accept(type_visitor& visitor) const
{
	visitor.visit(*this);
}

template <>
void lst::unsigned_enumeration_type::accept(type_visitor& visitor) const
{
	visitor.visit(*this);
}

lst::array_type::array_type(unsigned int in_alignment, type::cuptr in_element_type) :
	type(in_alignment), element_type{std::move(in_element_type)}
{
}

bool lst::array_type::_is_equal(const type& base_other) const noexcept
{
	const auto& other = static_cast<decltype(*this)&>(base_other);

	return *this->element_type == *other.element_type;
}

lst::static_length_array_type::static_length_array_type(unsigned int in_alignment,
		type::cuptr in_element_type,
		uint64_t in_length) :
	array_type(in_alignment, std::move(in_element_type)),
	length{in_length}
{
}

bool lst::static_length_array_type::_is_equal(const type& base_other) const noexcept
{
	const auto& other = static_cast<decltype(*this)&>(base_other);

	return array_type::_is_equal(base_other) && this->length == other.length;
}

void lst::static_length_array_type::accept(type_visitor& visitor) const
{
	visitor.visit(*this);
}

lst::dynamic_length_array_type::dynamic_length_array_type(unsigned int in_alignment,
		type::cuptr in_element_type,
		std::string in_length_field_name) :
	array_type(in_alignment, std::move(in_element_type)),
	length_field_name{std::move(in_length_field_name)}
{
}

bool lst::dynamic_length_array_type::_is_equal(const type& base_other) const noexcept
{
	const auto& other = static_cast<decltype(*this)&>(base_other);

	return array_type::_is_equal(base_other) &&
			this->length_field_name == other.length_field_name;
}

void lst::dynamic_length_array_type::accept(type_visitor& visitor) const
{
	visitor.visit(*this);
}

lst::string_type::string_type(unsigned int in_alignment, enum encoding in_encoding) :
	type(in_alignment), encoding{in_encoding}
{
}

bool lst::string_type::_is_equal(const type& base_other) const noexcept
{
	const auto& other = static_cast<decltype(*this)&>(base_other);

	return this->encoding == other.encoding;
}

lst::static_length_string_type::static_length_string_type(
		unsigned int in_alignment, enum encoding in_encoding, uint64_t in_length) :
	string_type(in_alignment, in_encoding), length{in_length}
{
}

bool lst::static_length_string_type::_is_equal(const type& base_other) const noexcept
{
	const auto& other = static_cast<decltype(*this)&>(base_other);

	return string_type::_is_equal(base_other) && this->length == other.length;
}

void lst::static_length_string_type::accept(type_visitor& visitor) const
{
	visitor.visit(*this);
}

lst::dynamic_length_string_type::dynamic_length_string_type(unsigned int in_alignment,
		enum encoding in_encoding,
		std::string in_length_field_name) :
	string_type(in_alignment, in_encoding), length_field_name{std::move(in_length_field_name)}
{
}

bool lst::dynamic_length_string_type::_is_equal(const type& base_other) const noexcept
{
	const auto& other = static_cast<decltype(*this)&>(base_other);

	return string_type::_is_equal(base_other) &&
			this->length_field_name == other.length_field_name;
}

void lst::dynamic_length_string_type::accept(type_visitor& visitor) const
{
	visitor.visit(*this);
}

lst::null_terminated_string_type::null_terminated_string_type(unsigned int in_alignment,
		enum encoding in_encoding) :
	string_type(in_alignment, in_encoding)
{
}

void lst::null_terminated_string_type::accept(type_visitor& visitor) const
{
	visitor.visit(*this);
}

lst::structure_type::structure_type(unsigned int in_alignment, fields in_fields) :
	type(in_alignment), _fields{std::move(in_fields)}
{
}

bool lst::structure_type::_is_equal(const type& base_other) const noexcept
{
	const auto &other = static_cast<decltype(*this)&>(base_other);

	return fields_are_equal(this->_fields, other._fields);
}

void lst::structure_type::accept(type_visitor& visitor) const
{
	visitor.visit(*this);
}

lst::variant_type::variant_type(unsigned int in_alignment,
		std::string in_tag_name,
		choices in_choices) :
	type(in_alignment),
	tag_name{std::move(in_tag_name)},
	_choices{std::move(in_choices)}
{
}

bool lst::variant_type::_is_equal(const type& base_other) const noexcept
{
	const auto &other = static_cast<decltype(*this)&>(base_other);

	return this->tag_name == other.tag_name &&
			fields_are_equal(this->_choices, other._choices);
}

void lst::variant_type::accept(type_visitor& visitor) const
{
	visitor.visit(*this);
}