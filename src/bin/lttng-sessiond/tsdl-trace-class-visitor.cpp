/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "clock-class.hpp"
#include "tsdl-trace-class-visitor.hpp"

#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/make-unique.hpp>
#include <common/scope-exit.hpp>
#include <common/uuid.hpp>

#include <vendor/optional.hpp>

#include <algorithm>
#include <array>
#include <locale>
#include <queue>
#include <set>
#include <stack>
#include <unordered_set>
#include <utility>

namespace lst = lttng::sessiond::trace;
namespace tsdl = lttng::sessiond::tsdl;

namespace {
const auto ctf_spec_major = 1;
const auto ctf_spec_minor = 8;

/*
 * Although the CTF v1.8 specification recommends ignoring any leading underscore, Some readers,
 * such as Babeltrace 1.x, expect special identifiers without a prepended underscore.
 */
const std::unordered_set<std::string> safe_tsdl_identifiers = { "stream_id",
								"packet_size",
								"content_size",
								"id",
								"v",
								"timestamp",
								"events_discarded",
								"packet_seq_num",
								"timestamp_begin",
								"timestamp_end",
								"cpu_id",
								"magic",
								"uuid",
								"stream_instance_id" };

/*
 * A previous implementation always prepended '_' to the identifiers in order to
 * side-step the problem of escaping TSDL keywords and ensuring identifiers
 * started with an alphabetic character.
 *
 * Changing this behaviour to a smarter algorithm would break readers that have
 * come to expect this initial underscore.
 */
std::string escape_tsdl_identifier(const std::string& original_identifier)
{
	if (original_identifier.size() == 0) {
		LTTNG_THROW_ERROR("Invalid 0-length identifier used in trace description");
	}

	if (safe_tsdl_identifiers.find(original_identifier) != safe_tsdl_identifiers.end()) {
		return original_identifier;
	}

	std::string new_identifier;
	/* Optimisticly assume most identifiers are valid and allocate the same length. */
	new_identifier.reserve(original_identifier.size());
	new_identifier = "_";

	/* Replace illegal characters by '_'. */
	std::locale c_locale{ "C" };
	for (const auto current_char : original_identifier) {
		if (!std::isalnum(current_char, c_locale) && current_char != '_') {
			new_identifier += '_';
		} else {
			new_identifier += current_char;
		}
	}

	return new_identifier;
}

std::string escape_tsdl_env_string_value(const std::string& original_string)
{
	std::string escaped_string;

	escaped_string.reserve(original_string.size());

	for (const auto c : original_string) {
		switch (c) {
		case '\n':
			escaped_string += "\\n";
			break;
		case '\\':
			escaped_string += "\\\\";
			break;
		case '"':
			escaped_string += "\"";
			break;
		default:
			escaped_string += c;
			break;
		}
	}

	return escaped_string;
}

/*
 * Variants produced by LTTng-UST contain TSDL-unsafe names. A variant/selector
 * sanitization pass is performed before serializing a trace class hierarchy to
 * TSDL.
 *
 * The variant_tsdl_keyword_sanitizer visitor is used to visit field before it
 * is handed-over to the actual TSDL-producing visitor.
 *
 * As it visits fields, the variant_tsdl_keyword_sanitizer populates a
 * "type_overrider" with TSDL-safe replacements for any variant or enumeration
 * that uses TSDL-unsafe identifiers (reserved keywords).
 *
 * The type_overrider, in turn, is used by the rest of the TSDL serialization
 * visitor (tsdl_field_visitor) to swap any TSDL-unsafe types with their
 * sanitized version.
 *
 * The tsdl_field_visitor owns the type_overrider and only briefly shares it
 * with the variant_tsdl_keyword_sanitizer which takes a reference to it.
 */
class variant_tsdl_keyword_sanitizer : public lttng::sessiond::trace::field_visitor,
				       public lttng::sessiond::trace::type_visitor {
public:
	using type_lookup_function = std::function<const lst::type&(const lst::field_location&)>;

	variant_tsdl_keyword_sanitizer(tsdl::details::type_overrider& type_overrides,
				       type_lookup_function lookup_type) :
		_type_overrides(type_overrides), _lookup_type(std::move(lookup_type))
	{
	}

private:
	class _c_string_comparator {
	public:
		int operator()(const char *lhs, const char *rhs) const
		{
			return std::strcmp(lhs, rhs) < 0;
		}
	};
	using unsafe_names = std::set<const char *, _c_string_comparator>;

	void visit(const lst::field& field) final
	{
		_type_overrides.type(field.get_type()).accept(*this);
	}

	void visit(const lst::integer_type& type __attribute__((unused))) final
	{
	}

	void visit(const lst::floating_point_type& type __attribute__((unused))) final
	{
	}

	void visit(const lst::signed_enumeration_type& type __attribute__((unused))) final
	{
	}

	void visit(const lst::unsigned_enumeration_type& type __attribute__((unused))) final
	{
	}

	void visit(const lst::static_length_array_type& type __attribute__((unused))) final
	{
	}

	void visit(const lst::dynamic_length_array_type& type __attribute__((unused))) final
	{
	}

	void visit(const lst::static_length_blob_type& type __attribute__((unused))) final
	{
	}

	void visit(const lst::dynamic_length_blob_type& type __attribute__((unused))) final
	{
	}

	void visit(const lst::null_terminated_string_type& type __attribute__((unused))) final
	{
	}

	void visit(const lst::structure_type& type) final
	{
		/* Recurse into structure attributes. */
		for (const auto& field : type.fields_) {
			field->accept(*this);
		}
	}

	/*
	 * Create a new enumeration type replacing any mapping that match, by name, the elements in
	 * `unsafe_names_found` with a TSDL-safe version. Currently, unsafe identifiers are made
	 * safe by adding a leading underscore.
	 */
	template <typename MappingIntegerType>
	lst::type::cuptr _create_sanitized_selector(
		const lst::typed_enumeration_type<MappingIntegerType>& original_selector,
		const unsafe_names& unsafe_names_found)
	{
		auto new_mappings = std::make_shared<
			typename lst::typed_enumeration_type<MappingIntegerType>::mappings>();

		for (const auto& mapping : *original_selector.mappings_) {
			if (unsafe_names_found.find(mapping.name.c_str()) ==
			    unsafe_names_found.end()) {
				/* Mapping is safe, simply copy it. */
				new_mappings->emplace_back(mapping);
			} else {
				/* Unsafe mapping, rename it and keep the rest of its attributes. */
				new_mappings->emplace_back(fmt::format("_{}", mapping.name),
							   mapping.range);
			}
		}

		return lttng::make_unique<lst::typed_enumeration_type<MappingIntegerType>>(
			original_selector.alignment,
			original_selector.byte_order,
			original_selector.size,
			original_selector.base_,
			new_mappings);
	}

	template <typename MappingIntegerType>
	const typename lst::typed_enumeration_type<MappingIntegerType>::mapping&
	_find_enumeration_mapping_by_range(
		const typename lst::typed_enumeration_type<MappingIntegerType>& enumeration_type,
		const typename lst::typed_enumeration_type<MappingIntegerType>::mapping::range_t&
			target_mapping_range)
	{
		for (const auto& mapping : *enumeration_type.mappings_) {
			if (mapping.range == target_mapping_range) {
				return mapping;
			}
		}

		LTTNG_THROW_ERROR(fmt::format(
			"Failed to find mapping by range in enumeration while sanitizing a variant: target_mapping_range={}",
			target_mapping_range));
	}

	/*
	 * Copy `original_variant`, but use the mappings of a previously-published sanitized tag
	 * to produce a TSDL-safe version of the variant.
	 */
	template <typename MappingIntegerType>
	lst::type::cuptr
	_create_sanitized_variant(const lst::variant_type<MappingIntegerType>& original_variant)
	{
		typename lst::variant_type<MappingIntegerType>::choices new_choices;
		const auto& sanitized_selector =
			static_cast<const lst::typed_enumeration_type<MappingIntegerType>&>(
				_type_overrides.type(
					_lookup_type(original_variant.selector_field_location)));

		/* Visit variant choices to sanitize them as needed. */
		for (const auto& choice : original_variant.choices_) {
			choice.second->accept(*this);
		}

		for (const auto& choice : original_variant.choices_) {
			const auto& sanitized_choice_type = _type_overrides.type(*choice.second);

			new_choices.emplace_back(_find_enumeration_mapping_by_range(
							 sanitized_selector, choice.first.range),
						 sanitized_choice_type.copy());
		}

		return lttng::make_unique<lst::variant_type<MappingIntegerType>>(
			original_variant.alignment,
			original_variant.selector_field_location,
			std::move(new_choices));
	}

	template <typename MappingIntegerType>
	void visit_variant(const lst::variant_type<MappingIntegerType>& type)
	{
		unsafe_names unsafe_names_found;
		static const std::unordered_set<std::string> tsdl_protected_keywords = {
			"align",  "callsite", "const",	   "char",	     "clock",	 "double",
			"enum",	  "env",      "event",	   "floating_point", "float",	 "integer",
			"int",	  "long",     "short",	   "signed",	     "stream",	 "string",
			"struct", "trace",    "typealias", "typedef",	     "unsigned", "variant",
			"void",	  "_Bool",    "_Complex",  "_Imaginary",
		};

		for (const auto& choice : type.choices_) {
			if (tsdl_protected_keywords.find(choice.first.name) !=
			    tsdl_protected_keywords.cend()) {
				/* Choice name is illegal, we have to rename it and its matching
				 * mapping. */
				unsafe_names_found.insert(choice.first.name.c_str());
			}
		}

		if (unsafe_names_found.empty()) {
			return;
		}

		/*
		 * Look-up selector field type.
		 *
		 * Since it may have been overriden previously, keep the original and overriden
		 * selector field types (which may be the same, if the original was not overriden).
		 *
		 * We work from the "overriden" selector field type to preserve any existing
		 * modifications. However, the original field type will be used to publish the new
		 * version of the type leaving only the most recent overriden type in the type
		 * overrides.
		 */
		const auto& original_selector_type = _lookup_type(type.selector_field_location);
		const auto& overriden_selector_type = _type_overrides.type(original_selector_type);

		auto sanitized_selector_type = _create_sanitized_selector(
			static_cast<const lst::typed_enumeration_type<MappingIntegerType>&>(
				overriden_selector_type),
			unsafe_names_found);
		_type_overrides.publish(original_selector_type, std::move(sanitized_selector_type));

		auto sanitized_variant_type = _create_sanitized_variant(
			static_cast<const lst::variant_type<MappingIntegerType>&>(type));
		_type_overrides.publish(type, std::move(sanitized_variant_type));
	}

	void visit(const lst::variant_type<
		   lst::signed_enumeration_type::mapping::range_t::range_integer_t>& type) final
	{
		visit_variant(type);
	}

	void visit(const lst::variant_type<
		   lst::unsigned_enumeration_type::mapping::range_t::range_integer_t>& type) final
	{
		visit_variant(type);
	}

	void visit(const lst::static_length_string_type& type __attribute__((unused))) final
	{
	}

	void visit(const lst::dynamic_length_string_type& type __attribute__((unused))) final
	{
	}

	tsdl::details::type_overrider& _type_overrides;
	const type_lookup_function _lookup_type;
};

class tsdl_field_visitor : public lttng::sessiond::trace::field_visitor,
			   public lttng::sessiond::trace::type_visitor {
public:
	tsdl_field_visitor(const lst::abi& abi,
			   unsigned int indentation_level,
			   const tsdl::details::type_overrider& type_overrides,
			   const nonstd::optional<std::string>& in_default_clock_class_name =
				   nonstd::nullopt) :
		_indentation_level(indentation_level),
		_trace_abi(abi),

		_default_clock_class_name(in_default_clock_class_name ?
						  in_default_clock_class_name->c_str() :
						  nullptr),
		_type_overrides(type_overrides)
	{
	}

	/* Only call once. */
	std::string move_description()
	{
		return std::move(_description);
	}

private:
	void visit(const lst::field& field) final
	{
		/*
		 * Hack: keep the name of the field being visited since
		 * the tracers can express sequences, variants, and arrays with an alignment
		 * constraint, which is not expressible in TSDL. To work around this limitation, an
		 * empty structure declaration is inserted when needed to express the aligment
		 * constraint. The name of this structure is generated using the field's name.
		 */
		_current_field_name.push(_bypass_identifier_escape ?
						 field.name :
						 escape_tsdl_identifier(field.name));
		_type_overrides.type(field.get_type()).accept(*this);
		_description += " ";
		_description += _current_field_name.top();
		_current_field_name.pop();

		/*
		 * Some types requires suffixes to be appended (e.g. the length of arrays
		 * and sequences, the mappings of enumerations).
		 */
		while (!_type_suffixes.empty()) {
			_description += _type_suffixes.front();
			_type_suffixes.pop();
		}

		_description += ";";
	}

	void visit(const lst::integer_type& type) final
	{
		_description += "integer { ";

		/* Mandatory properties (no defaults). */
		_description += fmt::format("size = {size}; align = {alignment};",
					    fmt::arg("size", type.size),
					    fmt::arg("alignment", type.alignment));

		/* Defaults to unsigned. */
		if (type.signedness_ == lst::integer_type::signedness::SIGNED) {
			_description += " signed = true;";
		}

		/* Defaults to 10. */
		if (type.base_ != lst::integer_type::base::DECIMAL) {
			unsigned int base;

			switch (type.base_) {
			case lst::integer_type::base::BINARY:
				base = 2;
				break;
			case lst::integer_type::base::OCTAL:
				base = 8;
				break;
			case lst::integer_type::base::HEXADECIMAL:
				base = 16;
				break;
			default:
				LTTNG_THROW_ERROR(fmt::format(
					"Unexpected base encountered while serializing integer type to TSDL: base = {}",
					(int) type.base_));
			}

			_description += fmt::format(" base = {};", base);
		}

		/* Defaults to the trace's native byte order. */
		if (type.byte_order != _trace_abi.byte_order) {
			const auto byte_order_str =
				type.byte_order == lst::byte_order::BIG_ENDIAN_ ? "be" : "le";

			_description += fmt::format(" byte_order = {};", byte_order_str);
		}

		if (_current_integer_encoding_override) {
			const char *encoding_str;

			switch (*_current_integer_encoding_override) {
			case lst::string_type::encoding::ASCII:
				encoding_str = "ASCII";
				break;
			case lst::string_type::encoding::UTF8:
				encoding_str = "UTF8";
				break;
			default:
				LTTNG_THROW_ERROR(fmt::format(
					"Unexpected encoding encountered while serializing integer type to TSDL: encoding = {}",
					(int) *_current_integer_encoding_override));
			}

			_description += fmt::format(" encoding = {};", encoding_str);
			_current_integer_encoding_override.reset();
		}

		if (std::find(type.roles_.begin(),
			      type.roles_.end(),
			      lst::integer_type::role::DEFAULT_CLOCK_TIMESTAMP) !=
			    type.roles_.end() ||
		    std::find(type.roles_.begin(),
			      type.roles_.end(),
			      lst::integer_type::role::PACKET_END_DEFAULT_CLOCK_TIMESTAMP) !=
			    type.roles_.end()) {
			LTTNG_ASSERT(_default_clock_class_name);
			_description +=
				fmt::format(" map = clock.{}.value;", _default_clock_class_name);
		}

		_description += " }";
	}

	void visit(const lst::floating_point_type& type) final
	{
		_description += fmt::format(
			"floating_point {{ align = {alignment}; mant_dig = {mantissa_digits}; exp_dig = {exponent_digits};",
			fmt::arg("alignment", type.alignment),
			fmt::arg("mantissa_digits", type.mantissa_digits),
			fmt::arg("exponent_digits", type.exponent_digits));

		/* Defaults to the trace's native byte order. */
		if (type.byte_order != _trace_abi.byte_order) {
			const auto byte_order_str =
				type.byte_order == lst::byte_order::BIG_ENDIAN_ ? "be" : "le";

			_description += fmt::format(" byte_order = {};", byte_order_str);
		}

		_description += " }";
	}

	template <class EnumerationType>
	void visit_enumeration(const EnumerationType& type)
	{
		/* name follows, when applicable. */
		_description += "enum : ";

		visit(static_cast<const lst::integer_type&>(type));
		_description += " {\n";

		const auto mappings_indentation_level = _indentation_level + 1;

		bool first_mapping = true;
		for (const auto& mapping : *type.mappings_) {
			if (!first_mapping) {
				_description += ",\n";
			}

			_description.resize(_description.size() + mappings_indentation_level, '\t');
			if (mapping.range.begin == mapping.range.end) {
				_description +=
					fmt::format("\"{mapping_name}\" = {mapping_value}",
						    fmt::arg("mapping_name", mapping.name),
						    fmt::arg("mapping_value", mapping.range.begin));
			} else {
				_description += fmt::format(
					"\"{mapping_name}\" = {mapping_range_begin} ... {mapping_range_end}",
					fmt::arg("mapping_name", mapping.name),
					fmt::arg("mapping_range_begin", mapping.range.begin),
					fmt::arg("mapping_range_end", mapping.range.end));
			}

			first_mapping = false;
		}

		_description += "\n";
		_description.resize(_description.size() + _indentation_level, '\t');
		_description += "}";
	}

	void visit(const lst::signed_enumeration_type& type) final
	{
		visit_enumeration(type);
	}

	void visit(const lst::unsigned_enumeration_type& type) final
	{
		visit_enumeration(type);
	}

	void visit(const lst::static_length_array_type& type) final
	{
		if (type.alignment != 0) {
			LTTNG_ASSERT(_current_field_name.size() > 0);
			_description += fmt::format(
				"struct {{ }} align({alignment}) {field_name}_padding;\n",
				fmt::arg("alignment", type.alignment),
				fmt::arg("field_name", _current_field_name.top()));
			_description.resize(_description.size() + _indentation_level, '\t');
		}

		type.element_type->accept(*this);
		_type_suffixes.emplace(fmt::format("[{}]", type.length));
	}

	void visit(const lst::dynamic_length_array_type& type) final
	{
		if (type.alignment != 0) {
			/*
			 * Note that this doesn't support nested sequences. For
			 * the moment, tracers can't express those. However, we
			 * could wrap nested sequences in structures, which
			 * would allow us to express alignment constraints.
			 */
			LTTNG_ASSERT(_current_field_name.size() > 0);
			_description += fmt::format(
				"struct {{ }} align({alignment}) {field_name}_padding;\n",
				fmt::arg("alignment", type.alignment),
				fmt::arg("field_name", _current_field_name.top()));
			_description.resize(_description.size() + _indentation_level, '\t');
		}

		type.element_type->accept(*this);
		_type_suffixes.emplace(fmt::format(
			"[{}]",
			_bypass_identifier_escape ?
				*(type.length_field_location.elements_.end() - 1) :
				escape_tsdl_identifier(
					*(type.length_field_location.elements_.end() - 1))));
	}

	void visit(const lst::static_length_blob_type& type) final
	{
		/* This type doesn't exist in CTF 1.x, express it as a static length array of
		 * uint8_t. */
		std::unique_ptr<const lst::type> uint8_element =
			lttng::make_unique<lst::integer_type>(
				8,
				_trace_abi.byte_order,
				8,
				lst::integer_type::signedness::UNSIGNED,
				lst::integer_type::base::HEXADECIMAL);
		const auto array = lttng::make_unique<lst::static_length_array_type>(
			type.alignment, std::move(uint8_element), type.length_bytes);

		visit(*array);
	}

	void visit(const lst::dynamic_length_blob_type& type) final
	{
		/* This type doesn't exist in CTF 1.x, express it as a dynamic length array of
		 * uint8_t. */
		std::unique_ptr<const lst::type> uint8_element =
			lttng::make_unique<lst::integer_type>(
				0,
				_trace_abi.byte_order,
				8,
				lst::integer_type::signedness::UNSIGNED,
				lst::integer_type::base::HEXADECIMAL);
		const auto array = lttng::make_unique<lst::dynamic_length_array_type>(
			type.alignment, std::move(uint8_element), type.length_field_location);

		visit(*array);
	}

	void visit(const lst::null_terminated_string_type& type) final
	{
		/* Defaults to UTF-8. */
		if (type.encoding_ == lst::null_terminated_string_type::encoding::ASCII) {
			_description += "string { encoding = ASCII }";
		} else {
			_description += "string";
		}
	}

	void visit(const lst::structure_type& type) final
	{
		_indentation_level++;
		_description += "struct {";

		const auto previous_bypass_identifier_escape = _bypass_identifier_escape;
		_bypass_identifier_escape = false;
		for (const auto& field : type.fields_) {
			_description += "\n";
			_description.resize(_description.size() + _indentation_level, '\t');
			field->accept(*this);
		}

		_bypass_identifier_escape = previous_bypass_identifier_escape;

		_indentation_level--;
		if (type.fields_.size() != 0) {
			_description += "\n";
			_description.resize(_description.size() + _indentation_level, '\t');
		}

		_description += "}";
	}

	template <class MappingIntegerType>
	void visit_variant(const lst::variant_type<MappingIntegerType>& type)
	{
		if (type.alignment != 0) {
			LTTNG_ASSERT(_current_field_name.size() > 0);
			_description += fmt::format(
				"struct {{ }} align({alignment}) {field_name}_padding;\n",
				fmt::arg("alignment", type.alignment),
				fmt::arg("field_name", _current_field_name.top()));
			_description.resize(_description.size() + _indentation_level, '\t');
		}

		_indentation_level++;
		_description += fmt::format(
			"variant <{}> {{\n",
			_bypass_identifier_escape ?
				*(type.selector_field_location.elements_.end() - 1) :
				escape_tsdl_identifier(
					*(type.selector_field_location.elements_.end() - 1)));

		/*
		 * The CTF 1.8 specification only recommends that implementations ignore
		 * leading underscores in field names. Both babeltrace 1 and 2 expect the
		 * variant choice and enumeration mapping name to match perfectly. Given that we
		 * don't have access to the tag in this context, we have to assume they match.
		 */
		const auto previous_bypass_identifier_escape = _bypass_identifier_escape;
		_bypass_identifier_escape = true;
		for (const auto& field : type.choices_) {
			_description.resize(_description.size() + _indentation_level, '\t');
			field.second->accept(*this);
			_description += fmt::format(" {};\n", field.first.name);
		}

		_bypass_identifier_escape = previous_bypass_identifier_escape;

		_indentation_level--;
		_description.resize(_description.size() + _indentation_level, '\t');
		_description += "}";
	}

	void visit(const lst::variant_type<
		   lst::signed_enumeration_type::mapping::range_t::range_integer_t>& type) final
	{
		visit_variant(type);
	}

	void visit(const lst::variant_type<
		   lst::unsigned_enumeration_type::mapping::range_t::range_integer_t>& type) final
	{
		visit_variant(type);
	}

	lst::type::cuptr create_character_type(enum lst::string_type::encoding encoding)
	{
		_current_integer_encoding_override = encoding;
		return lttng::make_unique<lst::integer_type>(
			8,
			_trace_abi.byte_order,
			8,
			lst::integer_type::signedness::UNSIGNED,
			lst::integer_type::base::DECIMAL);
	}

	void visit(const lst::static_length_string_type& type) final
	{
		/*
		 * TSDL expresses static-length strings as arrays of 8-bit integer with
		 * an encoding specified.
		 */
		const auto char_array = lttng::make_unique<lst::static_length_array_type>(
			type.alignment, create_character_type(type.encoding_), type.length);

		visit(*char_array);
	}

	void visit(const lst::dynamic_length_string_type& type) final
	{
		/*
		 * TSDL expresses dynamic-length strings as arrays of 8-bit integer with
		 * an encoding specified.
		 */
		const auto char_sequence = lttng::make_unique<lst::dynamic_length_array_type>(
			type.alignment,
			create_character_type(type.encoding_),
			type.length_field_location);

		visit(*char_sequence);
	}

	std::stack<std::string> _current_field_name;
	/*
	 * Encoding to specify for the next serialized integer type.
	 * Since the integer_type does not allow an encoding to be specified (it is a TSDL-specific
	 * concept), this attribute is used when expressing static or dynamic length strings as
	 * arrays/sequences of bytes with an encoding.
	 */
	nonstd::optional<enum lst::string_type::encoding> _current_integer_encoding_override;

	unsigned int _indentation_level;
	const lst::abi& _trace_abi;

	std::queue<std::string> _type_suffixes;

	/* Description in TSDL format. */
	std::string _description;

	bool _bypass_identifier_escape{ false };
	const char *_default_clock_class_name;
	const tsdl::details::type_overrider& _type_overrides;
};

class tsdl_trace_environment_visitor : public lst::trace_class_environment_visitor {
public:
	tsdl_trace_environment_visitor() = default;

	void visit(const lst::environment_field<int64_t>& field) override
	{
		_environment += fmt::format("	{} = {};\n", field.name, field.value);
	}

	void visit(const lst::environment_field<const char *>& field) override
	{
		_environment += fmt::format("	{} = \"{}\";\n",
					    field.name,
					    escape_tsdl_env_string_value(field.value));
	}

	/* Only call once. */
	std::string move_description()
	{
		_environment += "};\n\n";
		return std::move(_environment);
	}

private:
	std::string _environment{ "env {\n" };
};
} /* namespace */

tsdl::trace_class_visitor::trace_class_visitor(
	const lst::abi& trace_abi,
	tsdl::append_metadata_fragment_function append_metadata_fragment) :
	_trace_abi(trace_abi), _append_metadata_fragment(std::move(append_metadata_fragment))
{
}

void tsdl::trace_class_visitor::append_metadata_fragment(const std::string& fragment) const
{
	_append_metadata_fragment(fragment);
}

void tsdl::trace_class_visitor::visit(const lttng::sessiond::trace::trace_class& trace_class)
{
	/* Ensure this instance is not used against multiple trace classes. */
	LTTNG_ASSERT(!_current_trace_class || _current_trace_class == &trace_class);
	_current_trace_class = &trace_class;

	tsdl_field_visitor packet_header_visitor{ trace_class.abi, 1, _sanitized_types_overrides };

	trace_class.packet_header()->accept(packet_header_visitor);

	/* Declare type aliases, trace class, and packet header. */
	auto trace_class_tsdl = fmt::format(
		"/* CTF {ctf_major}.{ctf_minor} */\n\n"
		"trace {{\n"
		"	major = {ctf_major};\n"
		"	minor = {ctf_minor};\n"
		"	uuid = \"{uuid}\";\n"
		"	byte_order = {byte_order};\n"
		"	packet.header := {packet_header_layout};\n"
		"}};\n\n",
		fmt::arg("ctf_major", ctf_spec_major),
		fmt::arg("ctf_minor", ctf_spec_minor),
		fmt::arg("uint8_t_alignment", trace_class.abi.uint8_t_alignment),
		fmt::arg("uint16_t_alignment", trace_class.abi.uint16_t_alignment),
		fmt::arg("uint32_t_alignment", trace_class.abi.uint32_t_alignment),
		fmt::arg("uint64_t_alignment", trace_class.abi.uint64_t_alignment),
		fmt::arg("long_alignment", trace_class.abi.long_alignment),
		fmt::arg("long_size", trace_class.abi.long_alignment),
		fmt::arg("bits_per_long", trace_class.abi.bits_per_long),
		fmt::arg("uuid", lttng::utils::uuid_to_str(trace_class.uuid)),
		fmt::arg("byte_order",
			 trace_class.abi.byte_order == lst::byte_order::BIG_ENDIAN_ ? "be" : "le"),
		fmt::arg("packet_header_layout", packet_header_visitor.move_description()));

	/* Declare trace scope and type aliases. */
	append_metadata_fragment(trace_class_tsdl);

	tsdl_trace_environment_visitor environment_visitor;
	trace_class.accept(environment_visitor);
	append_metadata_fragment(environment_visitor.move_description());
}

void tsdl::trace_class_visitor::visit(const lttng::sessiond::trace::clock_class& clock_class)
{
	auto uuid_str = clock_class.uuid ?
		fmt::format("	uuid = \"{}\";\n", lttng::utils::uuid_to_str(*clock_class.uuid)) :
		"";

	/* Assumes a single clock that maps to specific stream class fields/roles. */
	auto clock_class_str = fmt::format("clock {{\n"
					   "	name = \"{name}\";\n"
					   /* Optional uuid. */
					   "{uuid}"
					   "	description = \"{description}\";\n"
					   "	freq = {frequency};\n"
					   "	offset = {offset};\n"
					   "}};\n"
					   "\n",
					   fmt::arg("name", clock_class.name),
					   fmt::arg("uuid", uuid_str),
					   fmt::arg("description", clock_class.description),
					   fmt::arg("frequency", clock_class.frequency),
					   fmt::arg("offset", clock_class.offset));

	append_metadata_fragment(clock_class_str);
}

void tsdl::trace_class_visitor::visit(const lttng::sessiond::trace::stream_class& stream_class)
{
	_current_stream_class = &stream_class;
	const auto clear_stream_class_on_exit =
		lttng::make_scope_exit([this]() noexcept { _current_stream_class = nullptr; });

	auto stream_class_str = fmt::format("stream {{\n"
					    "	id = {};\n",
					    stream_class.id);
	variant_tsdl_keyword_sanitizer variant_sanitizer(
		_sanitized_types_overrides,
		[this](const lttng::sessiond::trace::field_location& location) -> const lst::type& {
			return _lookup_field_type(location);
		});

	const auto *event_header = stream_class.event_header();
	if (event_header) {
		tsdl_field_visitor event_header_visitor{ _trace_abi,
							 1,
							 _sanitized_types_overrides,
							 stream_class.default_clock_class_name };

		event_header->accept(variant_sanitizer);
		event_header->accept(event_header_visitor);
		stream_class_str += fmt::format("	event.header := {};\n",
						event_header_visitor.move_description());
	}

	const auto *packet_context = stream_class.packet_context();
	if (packet_context) {
		tsdl_field_visitor packet_context_visitor{ _trace_abi,
							   1,
							   _sanitized_types_overrides,
							   stream_class.default_clock_class_name };

		packet_context->accept(variant_sanitizer);
		packet_context->accept(packet_context_visitor);
		stream_class_str += fmt::format("	packet.context := {};\n",
						packet_context_visitor.move_description());
	}

	const auto *event_context = stream_class.event_context();
	if (event_context) {
		tsdl_field_visitor event_context_visitor{ _trace_abi,
							  1,
							  _sanitized_types_overrides };

		event_context->accept(variant_sanitizer);
		event_context->accept(event_context_visitor);
		stream_class_str += fmt::format("	event.context := {};\n",
						event_context_visitor.move_description());
	}

	stream_class_str += "};\n\n";

	append_metadata_fragment(stream_class_str);
}

void tsdl::trace_class_visitor::visit(const lttng::sessiond::trace::event_class& event_class)
{
	_current_event_class = &event_class;
	const auto clear_event_class_on_exit =
		lttng::make_scope_exit([this]() noexcept { _current_event_class = nullptr; });

	auto event_class_str = fmt::format("event {{\n"
					   "	name = \"{name}\";\n"
					   "	id = {id};\n"
					   "	stream_id = {stream_class_id};\n"
					   "	loglevel = {log_level};\n",
					   fmt::arg("name", event_class.name),
					   fmt::arg("id", event_class.id),
					   fmt::arg("stream_class_id", event_class.stream_class_id),
					   fmt::arg("log_level", event_class.log_level));

	if (event_class.model_emf_uri) {
		event_class_str +=
			fmt::format("	model.emf.uri = \"{}\";\n", *event_class.model_emf_uri);
	}

	tsdl_field_visitor payload_visitor{ _trace_abi, 1, _sanitized_types_overrides };
	variant_tsdl_keyword_sanitizer variant_sanitizer(
		_sanitized_types_overrides,
		[this](const lttng::sessiond::trace::field_location& location) -> const lst::type& {
			return _lookup_field_type(location);
		});

	event_class.payload->accept(variant_sanitizer);
	event_class.payload->accept(payload_visitor);

	event_class_str +=
		fmt::format("	fields := {};\n}};\n\n", payload_visitor.move_description());

	append_metadata_fragment(event_class_str);
}

void tsdl::details::type_overrider::publish(const lttng::sessiond::trace::type& original_type,
					    lttng::sessiond::trace::type::cuptr new_type_override)
{
	auto current_override = _overriden_types.find(&original_type);

	if (current_override != _overriden_types.end()) {
		current_override->second = std::move(new_type_override);
	} else {
		_overriden_types.insert(
			std::make_pair(&original_type, std::move(new_type_override)));
	}
}

const lst::type&
tsdl::details::type_overrider::type(const lttng::sessiond::trace::type& original) const noexcept
{
	const auto result = _overriden_types.find(&original);

	if (result != _overriden_types.end()) {
		/* Provide the overriden type. */
		return *result->second;
	}

	/* Pass the original type through. */
	return original;
}

namespace {
const lttng::sessiond::trace::type&
lookup_type_from_root_type(const lttng::sessiond::trace::type& root_type,
			   const lttng::sessiond::trace::field_location& field_location)
{
	const auto *type = &root_type;

	for (const auto& location_element : field_location.elements_) {
		/* Only structures can be traversed. */
		const auto *struct_type = dynamic_cast<const lst::structure_type *>(type);

		/*
		 * Traverse the type by following the field location path.
		 *
		 * While field paths are assumed to have been validated before-hand,
		 * a dynamic cast is performed here as an additional precaution
		 * since none of this is performance-critical; it can be removed
		 * safely.
		 */
		if (!struct_type) {
			LTTNG_THROW_ERROR(fmt::format(
				"Encountered a type that is not a structure while traversing field location: field-location=`{}`",
				field_location));
		}

		const auto field_found_it =
			std::find_if(struct_type->fields_.cbegin(),
				     struct_type->fields_.cend(),
				     [&location_element](const lst::field::cuptr& struct_field) {
					     return struct_field->name == location_element;
				     });

		if (field_found_it == struct_type->fields_.cend()) {
			LTTNG_THROW_ERROR(fmt::format(
				"Failed to find field using field location: field-name:=`{field_name}`, field-location=`{field_location}`",
				fmt::arg("field_location", field_location),
				fmt::arg("field_name", location_element)));
		}

		type = &(*field_found_it)->get_type();
	}

	return *type;
}
} /* anonymous namespace. */

/*
 * The trace hierarchy is assumed to have been validated on creation.
 * This function can only fail due to a validation error, hence
 * why it throws on any unexpected/invalid field location.
 *
 * Does not return an overriden field type; it returns the original field type
 * as found in the trace hierarchy.
 */
const lttng::sessiond::trace::type& lttng::sessiond::tsdl::trace_class_visitor::_lookup_field_type(
	const lttng::sessiond::trace::field_location& location) const
{
	/* Validate the look-up is happening in a valid visit context. */
	switch (location.root_) {
	case lst::field_location::root::EVENT_RECORD_HEADER:
	case lst::field_location::root::EVENT_RECORD_PAYLOAD:
		if (!_current_event_class) {
			LTTNG_THROW_ERROR(
				"Field type look-up failure: no current event class in visitor's context");
		}
		/* fall through. */
	case lst::field_location::root::EVENT_RECORD_COMMON_CONTEXT:
	case lst::field_location::root::PACKET_CONTEXT:
		if (!_current_stream_class) {
			LTTNG_THROW_ERROR(
				"Field type look-up failure: no current stream class in visitor's context");
		}
		/* fall through. */
	case lst::field_location::root::PACKET_HEADER:
		if (!_current_trace_class) {
			LTTNG_THROW_ERROR(
				"Field type look-up failure: no current trace class in visitor's context");
		}

		break;
	case lst::field_location::root::EVENT_RECORD_SPECIFIC_CONTEXT:
		LTTNG_THROW_UNSUPPORTED_ERROR(
			"Field type look-up failure: event-record specific contexts are not supported");
	default:
		LTTNG_THROW_UNSUPPORTED_ERROR(
			"Field type look-up failure: unknown field location root");
	}

	switch (location.root_) {
	case lst::field_location::root::PACKET_HEADER:
		return lookup_type_from_root_type(*_current_trace_class->packet_header(), location);
	case lst::field_location::root::PACKET_CONTEXT:
		return lookup_type_from_root_type(*_current_stream_class->packet_context(),
						  location);
	case lst::field_location::root::EVENT_RECORD_HEADER:
		return lookup_type_from_root_type(*_current_stream_class->event_header(), location);
	case lst::field_location::root::EVENT_RECORD_COMMON_CONTEXT:
		return lookup_type_from_root_type(*_current_stream_class->event_context(),
						  location);
	case lst::field_location::root::EVENT_RECORD_PAYLOAD:
		return lookup_type_from_root_type(*_current_event_class->payload, location);
	case lst::field_location::root::EVENT_RECORD_SPECIFIC_CONTEXT:
	default:
		/* Unreachable as it was checked before. */
		abort();
	}
}
