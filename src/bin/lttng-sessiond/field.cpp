/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "field.hpp"

#include <common/exception.hpp>
#include <common/format.hpp>

#include <set>

namespace lst = lttng::sessiond::trace;

namespace {
template <class FieldTypeContainerType>
bool fields_are_equal(const FieldTypeContainerType& a, const FieldTypeContainerType& b)
{
	if (a.size() != b.size()) {
		return false;
	}

	return std::equal(a.cbegin(),
			  a.cend(),
			  b.cbegin(),
			  [](typename FieldTypeContainerType::const_reference field_a,
			     typename FieldTypeContainerType::const_reference field_b) {
				  return *field_a == *field_b;
			  });
}
} /* namespace */

lst::field_location::field_location(lst::field_location::root in_lookup_root,
				    lst::field_location::elements in_elements) :
	root_{ in_lookup_root }, elements_{ std::move(in_elements) }
{
}

bool lst::field_location::operator==(const lst::field_location& other) const noexcept
{
	return root_ == other.root_ && elements_ == other.elements_;
}

lst::type::type(unsigned int in_alignment) : alignment{ in_alignment }
{
}

lst::type::~type() = default;

bool lst::type::operator==(const lst::type& other) const noexcept
{
	return typeid(*this) == typeid(other) && alignment == other.alignment &&
		/* defer to concrete type comparison */
		this->_is_equal(other);
}

bool lst::type::operator!=(const lst::type& other) const noexcept
{
	return !(*this == other);
}

lst::field::field(std::string in_name, lst::type::cuptr in_type) :
	name{ std::move(in_name) }, _type{ std::move(in_type) }
{
	if (!_type) {
		LTTNG_THROW_ERROR(lttng::format(
			"Invalid type used to create field: field name = `{}`", name));
	}
}

void lst::field::accept(lst::field_visitor& visitor) const
{
	visitor.visit(*this);
}

bool lst::field::operator==(const lst::field& other) const noexcept
{
	return name == other.name && *_type == *other._type;
}

lst::type::cuptr lst::field::move_type() noexcept
{
	return std::move(_type);
}

const lst::type& lst::field::get_type() const
{
	if (_type) {
		return *_type;
	} else {
		LTTNG_THROW_ERROR(lttng::format(
			"Invalid attempt to access field type after transfer: field name = `{}`",
			name));
	}
}

lst::integer_type::integer_type(unsigned int in_alignment,
				enum lst::byte_order in_byte_order,
				unsigned int in_size,
				enum lst::integer_type::signedness in_signedness,
				enum lst::integer_type::base in_base,
				roles in_roles) :
	type(in_alignment),
	byte_order{ in_byte_order },
	size{ in_size },
	signedness_{ in_signedness },
	base_{ in_base },
	roles_{ std::move(in_roles) }
{
}

lst::type::cuptr lst::integer_type::copy() const
{
	return lttng::make_unique<integer_type>(
		alignment, byte_order, size, signedness_, base_, roles_);
}

bool lst::integer_type::_is_equal(const type& base_other) const noexcept
{
	const auto& other = static_cast<decltype(*this)&>(base_other);

	return this->byte_order == other.byte_order && this->size == other.size &&
		this->signedness_ == other.signedness_ && this->base_ == other.base_ &&
		this->roles_ == other.roles_;
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
	exponent_digits{ in_exponent_digits },
	mantissa_digits(in_mantissa_digits)
{
	/* Allowed (exponent, mantissa) pairs. */
	static const std::set<std::pair<unsigned int, unsigned int>> allowed_pairs{
		{ 5, 11 }, /* binary16 */
		{ 8, 24 }, /* binary32 */
		{ 11, 53 }, /* binary64 */
		{ 15, 113 }, /* binary128 */
	};

	if (allowed_pairs.find({ exponent_digits, mantissa_digits }) != allowed_pairs.end()) {
		/* mantissa and exponent digits is a valid pair. */
		return;
	}

	LTTNG_THROW_INVALID_ARGUMENT_ERROR(lttng::format(
		"Invalid exponent/mantissa values provided while creating {}", typeid(*this)));
}

lst::type::cuptr lst::floating_point_type::copy() const
{
	return lttng::make_unique<floating_point_type>(
		alignment, byte_order, exponent_digits, mantissa_digits);
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
					enum base in_base,
					lst::integer_type::roles in_roles) :
	integer_type(
		in_alignment, in_byte_order, in_size, in_signedness, in_base, std::move(in_roles))
{
}

/*
 * Due to a bug in g++ < 7.1, these specializations must be enclosed in the namespaces
 * rather than using the usual `namespace::namespace::function` notation:
 * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56480.
 */
namespace lttng {
namespace sessiond {
namespace trace {
template <>
void signed_enumeration_type::accept(type_visitor& visitor) const
{
	visitor.visit(*this);
}

template <>
void unsigned_enumeration_type::accept(type_visitor& visitor) const
{
	visitor.visit(*this);
}

template <>
void variant_type<lst::signed_enumeration_type::mapping::range_t::range_integer_t>::accept(
	lst::type_visitor& visitor) const
{
	visitor.visit(*this);
}

template <>
void variant_type<lst::unsigned_enumeration_type::mapping::range_t::range_integer_t>::accept(
	lst::type_visitor& visitor) const
{
	visitor.visit(*this);
}
} /* namespace trace */
} /* namespace sessiond */
} /* namespace lttng */

lst::array_type::array_type(unsigned int in_alignment, type::cuptr in_element_type) :
	type(in_alignment), element_type{ std::move(in_element_type) }
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
	array_type(in_alignment, std::move(in_element_type)), length{ in_length }
{
}

bool lst::static_length_array_type::_is_equal(const type& base_other) const noexcept
{
	const auto& other = static_cast<decltype(*this)&>(base_other);

	return array_type::_is_equal(base_other) && this->length == other.length;
}

lst::type::cuptr lst::static_length_array_type::copy() const
{
	return lttng::make_unique<static_length_array_type>(
		alignment, element_type->copy(), length);
}

void lst::static_length_array_type::accept(type_visitor& visitor) const
{
	visitor.visit(*this);
}

lst::dynamic_length_array_type::dynamic_length_array_type(
	unsigned int in_alignment,
	type::cuptr in_element_type,
	lst::field_location in_length_field_location) :
	array_type(in_alignment, std::move(in_element_type)),
	length_field_location{ std::move(in_length_field_location) }
{
}

bool lst::dynamic_length_array_type::_is_equal(const type& base_other) const noexcept
{
	const auto& other = static_cast<decltype(*this)&>(base_other);

	return array_type::_is_equal(base_other) &&
		this->length_field_location == other.length_field_location;
}

lst::type::cuptr lst::dynamic_length_array_type::copy() const
{
	return lttng::make_unique<dynamic_length_array_type>(
		alignment, element_type->copy(), length_field_location);
}

void lst::dynamic_length_array_type::accept(type_visitor& visitor) const
{
	visitor.visit(*this);
}

lst::static_length_blob_type::static_length_blob_type(unsigned int in_alignment,
						      uint64_t in_length_bytes,
						      roles in_roles) :
	type(in_alignment), length_bytes{ in_length_bytes }, roles_{ std::move(in_roles) }
{
}

bool lst::static_length_blob_type::_is_equal(const type& base_other) const noexcept
{
	const auto& other = static_cast<decltype(*this)&>(base_other);

	return length_bytes == other.length_bytes && roles_ == other.roles_;
}

lst::type::cuptr lst::static_length_blob_type::copy() const
{
	return lttng::make_unique<static_length_blob_type>(alignment, length_bytes, roles_);
}

void lst::static_length_blob_type::accept(type_visitor& visitor) const
{
	visitor.visit(*this);
}

lst::dynamic_length_blob_type::dynamic_length_blob_type(
	unsigned int in_alignment, lst::field_location in_length_field_location) :
	type(in_alignment), length_field_location{ std::move(in_length_field_location) }
{
}

bool lst::dynamic_length_blob_type::_is_equal(const type& base_other) const noexcept
{
	const auto& other = dynamic_cast<decltype(*this)&>(base_other);

	return length_field_location == other.length_field_location;
}

lst::type::cuptr lst::dynamic_length_blob_type::copy() const
{
	return lttng::make_unique<dynamic_length_blob_type>(alignment, length_field_location);
}

void lst::dynamic_length_blob_type::accept(type_visitor& visitor) const
{
	visitor.visit(*this);
}

lst::string_type::string_type(unsigned int in_alignment, enum encoding in_encoding) :
	type(in_alignment), encoding_{ in_encoding }
{
}

bool lst::string_type::_is_equal(const type& base_other) const noexcept
{
	const auto& other = static_cast<decltype(*this)&>(base_other);

	return this->encoding_ == other.encoding_;
}

lst::static_length_string_type::static_length_string_type(unsigned int in_alignment,
							  enum encoding in_encoding,
							  uint64_t in_length) :
	string_type(in_alignment, in_encoding), length{ in_length }
{
}

bool lst::static_length_string_type::_is_equal(const type& base_other) const noexcept
{
	const auto& other = static_cast<decltype(*this)&>(base_other);

	return string_type::_is_equal(base_other) && this->length == other.length;
}

lst::type::cuptr lst::static_length_string_type::copy() const
{
	return lttng::make_unique<static_length_string_type>(alignment, encoding_, length);
}

void lst::static_length_string_type::accept(type_visitor& visitor) const
{
	visitor.visit(*this);
}

lst::dynamic_length_string_type::dynamic_length_string_type(
	unsigned int in_alignment,
	enum encoding in_encoding,
	field_location in_length_field_location) :
	string_type(in_alignment, in_encoding),
	length_field_location{ std::move(in_length_field_location) }
{
}

bool lst::dynamic_length_string_type::_is_equal(const type& base_other) const noexcept
{
	const auto& other = static_cast<decltype(*this)&>(base_other);

	return string_type::_is_equal(base_other) &&
		this->length_field_location == other.length_field_location;
}

lst::type::cuptr lst::dynamic_length_string_type::copy() const
{
	return lttng::make_unique<dynamic_length_string_type>(
		alignment, encoding_, length_field_location);
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

lst::type::cuptr lst::null_terminated_string_type::copy() const
{
	return lttng::make_unique<null_terminated_string_type>(alignment, encoding_);
}

void lst::null_terminated_string_type::accept(type_visitor& visitor) const
{
	visitor.visit(*this);
}

lst::structure_type::structure_type(unsigned int in_alignment, fields in_fields) :
	type(in_alignment), fields_{ std::move(in_fields) }
{
}

bool lst::structure_type::_is_equal(const type& base_other) const noexcept
{
	const auto& other = static_cast<decltype(*this)&>(base_other);

	return fields_are_equal(this->fields_, other.fields_);
}

lst::type::cuptr lst::structure_type::copy() const
{
	structure_type::fields copy_of_fields;

	copy_of_fields.reserve(fields_.size());
	for (const auto& field : fields_) {
		copy_of_fields.emplace_back(
			lttng::make_unique<lst::field>(field->name, field->get_type().copy()));
	}

	return lttng::make_unique<structure_type>(alignment, std::move(copy_of_fields));
}

void lst::structure_type::accept(type_visitor& visitor) const
{
	visitor.visit(*this);
}
