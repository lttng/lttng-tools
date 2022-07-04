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
#include <common/uuid.hpp>

#include <array>
#include <queue>
#include <locale>

namespace lst = lttng::sessiond::trace;
namespace tsdl = lttng::sessiond::tsdl;

namespace {
const auto ctf_spec_major = 1;
const auto ctf_spec_minor = 8;

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

	std::string new_identifier;
	/* Optimisticly assume most identifiers are valid and allocate the same length. */
	new_identifier.reserve(original_identifier.size());
	new_identifier = "_";

	/* Replace illegal characters by '_'. */
	std::locale c_locale{"C"};
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

class tsdl_field_visitor : public lttng::sessiond::trace::field_visitor,
			   public lttng::sessiond::trace::type_visitor {
public:
	tsdl_field_visitor(const lst::abi& abi, unsigned int indentation_level) :
		_indentation_level{indentation_level}, _trace_abi{abi}
	{
	}

	std::string& get_description()
	{
		return _description;
	}

private:
	virtual void visit(const lst::field& field) override final
	{
		/*
		 * Hack: keep the name of the field being visited since
		 * the tracers can express sequences, variants, and arrays with an alignment
		 * constraint, which is not expressible in TSDL. To work around this limitation, an
		 * empty structure declaration is inserted when needed to express the aligment
		 * constraint. The name of this structure is generated using the field's name.
		 */
		_escaped_current_field_name = escape_tsdl_identifier(field.name);

		field._type->accept(*this);
		_description += " ";
		_description += _escaped_current_field_name;

		/*
		 * Some types requires suffixes to be appended (e.g. the length of arrays
		 * and sequences, the mappings of enumerations).
		 */
		while (!_type_suffixes.empty()) {
			_description += _type_suffixes.front();
			_type_suffixes.pop();
		}

		_description += ";";
		_escaped_current_field_name.clear();
	}

	virtual void visit(const lst::integer_type& type) override final
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
			const auto byte_order_str = type.byte_order == lst::byte_order::BIG_ENDIAN_ ? "be" : "le";

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

		_description += " }";
	}

	virtual void visit(const lst::floating_point_type& type) override final
	{
		_description += fmt::format(
				"floating_point {{ align = {alignment}; mant_dig = {mantissa_digits}; exp_dig = {exponent_digits};",
				fmt::arg("alignment", type.alignment),
				fmt::arg("mantissa_digits", type.mantissa_digits),
				fmt::arg("exponent_digits", type.exponent_digits));

		/* Defaults to the trace's native byte order. */
		if (type.byte_order != _trace_abi.byte_order) {
			const auto byte_order_str = type.byte_order == lst::byte_order::BIG_ENDIAN_ ? "be" : "le";

			_description += fmt::format(" byte_order = {};", byte_order_str);
		}

		_description += " }";
	}

	template <class EnumerationType>
	void visit_enumeration(const EnumerationType& type)
	{
		/* name follows, when applicable. */
		_description += "enum : ";

		tsdl_field_visitor integer_visitor{_trace_abi, _indentation_level};

		integer_visitor.visit(static_cast<const lst::integer_type&>(type));
		_description += integer_visitor.get_description() + " {\n";

		const auto mappings_indentation_level = _indentation_level + 1;

		bool first_mapping = true;
		for (const auto& mapping : *type._mappings) {
			if (!first_mapping) {
				_description += ",\n";
			}

			_description.resize(_description.size() + mappings_indentation_level, '\t');
			if (!mapping.range) {
				_description += fmt::format("\"{}\"", mapping.name);
			} else if (mapping.range->begin == mapping.range->end) {
				_description += fmt::format(
						"\"{mapping_name}\" = {mapping_value}",
						fmt::arg("mapping_name", mapping.name),
						fmt::arg("mapping_value", mapping.range->begin));
			} else {
				_description += fmt::format(
						"\"{mapping_name}\" = {mapping_range_begin} ... {mapping_range_end}",
						fmt::arg("mapping_name", mapping.name),
						fmt::arg("mapping_range_begin",
								mapping.range->begin),
						fmt::arg("mapping_range_end", mapping.range->end));
			}

			first_mapping = false;
		}

		_description += "\n";
		_description.resize(_description.size() + _indentation_level, '\t');
		_description += "}";
	}

	virtual void visit(const lst::signed_enumeration_type& type) override final
	{
		visit_enumeration(type);
	}

	virtual void visit(const lst::unsigned_enumeration_type& type) override final
	{
		visit_enumeration(type);
	}

	virtual void visit(const lst::static_length_array_type& type) override final
	{
		if (type.alignment != 0) {
			LTTNG_ASSERT(_escaped_current_field_name.size() > 0);
			_description += fmt::format(
					"struct {{ }} align({alignment}) {field_name}_padding;\n",
					fmt::arg("alignment", type.alignment),
					fmt::arg("field_name", _escaped_current_field_name));
			_description.resize(_description.size() + _indentation_level, '\t');
		}

		type.element_type->accept(*this);
		_type_suffixes.emplace(fmt::format("[{}]", type.length));
	}

	virtual void visit(const lst::dynamic_length_array_type& type) override final
	{
		if (type.alignment != 0) {
			/*
			 * Note that this doesn't support nested sequences. For
			 * the moment, tracers can't express those. However, we
			 * could wrap nested sequences in structures, which
			 * would allow us to express alignment constraints.
			 */
			LTTNG_ASSERT(_escaped_current_field_name.size() > 0);
			_description += fmt::format(
					"struct {{ }} align({alignment}) {field_name}_padding;\n",
					fmt::arg("alignment", type.alignment),
					fmt::arg("field_name", _escaped_current_field_name));
			_description.resize(_description.size() + _indentation_level, '\t');
		}

		type.element_type->accept(*this);
		_type_suffixes.emplace(fmt::format(
				"[{}]", escape_tsdl_identifier(type.length_field_name)));
	}

	virtual void visit(const lst::static_length_blob_type& type) override final
	{
		/* This type doesn't exist in CTF 1.x, express it as a static length array of uint8_t. */
		std::unique_ptr<const lst::type> uint8_element = lttng::make_unique<lst::integer_type>(8,
				_trace_abi.byte_order, 8, lst::integer_type::signedness::UNSIGNED,
				lst::integer_type::base::HEXADECIMAL);
		const auto array = lttng::make_unique<lst::static_length_array_type>(
				type.alignment, std::move(uint8_element), type.length_bytes);

		visit(*array);
	}

	virtual void visit(const lst::dynamic_length_blob_type& type) override final
	{
		/* This type doesn't exist in CTF 1.x, express it as a dynamic length array of uint8_t. */
		std::unique_ptr<const lst::type> uint8_element = lttng::make_unique<lst::integer_type>(0,
				_trace_abi.byte_order, 8, lst::integer_type::signedness::UNSIGNED,
				lst::integer_type::base::HEXADECIMAL);
		const auto array = lttng::make_unique<lst::dynamic_length_array_type>(
				type.alignment, std::move(uint8_element), type.length_field_name);

		visit(*array);
	}

	virtual void visit(const lst::null_terminated_string_type& type) override final
	{
		/* Defaults to UTF-8.  */
		if (type.encoding_ == lst::null_terminated_string_type::encoding::ASCII) {
			_description += "string { encoding = ASCII }";
		} else {
			_description += "string";
		}
	}

	virtual void visit(const lst::structure_type& type) override final
	{
		_indentation_level++;
		_description += "struct {";

		for (const auto& field : type._fields) {
			_description += "\n";
			_description.resize(_description.size() + _indentation_level, '\t');
			field->accept(*this);
		}

		_indentation_level--;
		if (type._fields.size() != 0) {
			_description += "\n";
			_description.resize(_description.size() + _indentation_level, '\t');
		}

		_description += "};";
	}

	virtual void visit(const lst::variant_type& type) override final
	{
		if (type.alignment != 0) {
			LTTNG_ASSERT(_escaped_current_field_name.size() > 0);
			_description += fmt::format(
					"struct {{ }} align({alignment}) {field_name}_padding;\n",
					fmt::arg("alignment", type.alignment),
					fmt::arg("field_name", _escaped_current_field_name));
			_description.resize(_description.size() + _indentation_level, '\t');
		}

		_indentation_level++;
		_description += fmt::format("variant <{}> {\n", escape_tsdl_identifier(type.tag_name));

		bool first_field = true;
		for (const auto& field : type._choices) {
			if (!first_field) {
				_description += ",\n";
			}

			_description.resize(_description.size() + _indentation_level, '\t');
			field->accept(*this);
			first_field = false;
		}

		_description += "\n";
		_description.resize(_description.size() + _indentation_level, '\t');
		_description += "};";
		_indentation_level--;
	}

	lst::type::cuptr create_character_type(enum lst::string_type::encoding encoding)
	{
		_current_integer_encoding_override = encoding;
		return lttng::make_unique<lst::integer_type>(8, _trace_abi.byte_order, 8,
				lst::integer_type::signedness::UNSIGNED,
				lst::integer_type::base::DECIMAL);
	}

	virtual void visit(const lst::static_length_string_type& type) override final
	{
		/*
		 * TSDL expresses static-length strings as arrays of 8-bit integer with
		 * an encoding specified.
		 */
		const auto char_array = lttng::make_unique<lst::static_length_array_type>(
				type.alignment, create_character_type(type.encoding_), type.length);

		visit(*char_array);
	}

	virtual void visit(const lst::dynamic_length_string_type& type) override final
	{
		/*
		 * TSDL expresses dynamic-length strings as arrays of 8-bit integer with
		 * an encoding specified.
		 */
		const auto char_sequence = lttng::make_unique<lst::dynamic_length_array_type>(
				type.alignment, create_character_type(type.encoding_),
				type.length_field_name);

		visit(*char_sequence);
	}

	std::string _escaped_current_field_name;
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
};
} /* namespace */

tsdl::trace_class_visitor::trace_class_visitor(const lst::abi& trace_abi,
		tsdl::append_metadata_fragment_function append_metadata_fragment) :
	_trace_abi{trace_abi}, _append_metadata_fragment(append_metadata_fragment)
{
}

void tsdl::trace_class_visitor::append_metadata_fragment(const std::string& fragment) const
{
	_append_metadata_fragment(fragment);
}

void tsdl::trace_class_visitor::visit(const lttng::sessiond::trace::trace_class& trace_class)
{
	/* Declare type aliases, trace class, and packet header. */
	auto trace_class_tsdl = fmt::format(
			"/* CTF {ctf_major}.{ctf_minor} */\n\n"
			"typealias integer {{ size = 8; align = {uint8_t_alignment}; signed = false; }} := uint8_t;\n"
			"typealias integer {{ size = 16; align = {uint16_t_alignment}; signed = false; }} := uint16_t;\n"
			"typealias integer {{ size = 32; align = {uint32_t_alignment}; signed = false; }} := uint32_t;\n"
			"typealias integer {{ size = 64; align = {uint64_t_alignment}; signed = false; }} := uint64_t;\n"
			"typealias integer {{ size = {bits_per_long}; align = {long_alignment}; signed = false; }} := unsigned long;\n"
			"typealias integer {{ size = 5; align = 1; signed = false; }} := uint5_t;\n"
			"typealias integer {{ size = 27; align = 1; signed = false; }} := uint27_t;\n"
			"\n"
			"trace {{\n"
			"	major = {ctf_major};\n"
			"	minor = {ctf_minor};\n"
			"	uuid = \"{uuid}\";\n"
			"	byte_order = {byte_order};\n"
			"	packet.header := struct {{\n"
			"		uint32_t magic;\n"
			"		uint8_t  uuid[16];\n"
			"		uint32_t stream_id;\n"
			"		uint64_t stream_instance_id;\n"
			"	}};\n"
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
					trace_class.abi.byte_order == lst::byte_order::BIG_ENDIAN_ ?
							"be" :
							      "le"));

	/* Declare trace scope and type aliases. */
	append_metadata_fragment(std::move(trace_class_tsdl));
}

void tsdl::trace_class_visitor::visit(const lttng::sessiond::trace::clock_class& clock_class)
{
	auto uuid_str = clock_class.uuid ?
			fmt::format("	uuid = \"{}\";\n",
					lttng::utils::uuid_to_str(*clock_class.uuid)) :
			      "";

	/* Assumes a single clock that maps to specific stream class fields/roles. */
	auto clock_class_str = fmt::format(
			"clock {{\n"
			"	name = \"{name}\";\n"
			/* Optional uuid. */
			"{uuid}"
			"	description = \"{description}\";\n"
			"	freq = {frequency};\n"
			"	offset = {offset};\n"
			"}};\n"
			"\n"
			"typealias integer {{\n"
			"	size = 27; align = 1; signed = false;\n"
			"	map = clock.{name}.value;\n"
			"}} := uint27_clock_{name}_t;\n"
			"\n"
			"typealias integer {{\n"
			"	size = 32; align = {uint32_t_alignment}; signed = false;\n"
			"	map = clock.{name}.value;\n"
			"}} := uint32_clock_{name}_t;\n"
			"\n"
			"typealias integer {{\n"
			"	size = 64; align = {uint64_t_alignment}; signed = false;\n"
			"	map = clock.{name}.value;\n"
			"}} := uint64_clock_{name}_t;\n"
			"\n"
			"struct packet_context {{\n"
			"	uint64_clock_{name}_t timestamp_begin;\n"
			"	uint64_clock_{name}_t timestamp_end;\n"
			"	uint64_t content_size;\n"
			"	uint64_t packet_size;\n"
			"	uint64_t packet_seq_num;\n"
			"	unsigned long events_discarded;\n"
			"	uint32_t cpu_id;\n"
			"}};\n"
			"\n"
			"struct event_header_compact {{\n"
			"	enum : uint5_t {{ compact = 0 ... 30, extended = 31 }} id;\n"
			"	variant <id> {{\n"
			"		struct {{\n"
			"			uint27_clock_{name}_t timestamp;\n"
			"		}} compact;\n"
			"		struct {{\n"
			"			uint32_t id;\n"
			"			uint64_clock_{name}_t timestamp;\n"
			"		}} extended;\n"
			"	}} v;\n"
			"}} align({uint32_t_alignment});\n"
			"\n"
			"struct event_header_large {{\n"
			"	enum : uint16_t {{ compact = 0 ... 65534, extended = 65535 }} id;\n"
			"	variant <id> {{\n"
			"		struct {{\n"
			"			uint32_clock_{name}_t timestamp;\n"
			"		}} compact;\n"
			"		struct {{\n"
			"			uint32_t id;\n"
			"			uint64_clock_{name}_t timestamp;\n"
			"		}} extended;\n"
			"	}} v;\n"
			"}} align({uint16_t_alignment});\n\n",
			fmt::arg("name", clock_class.name),
			fmt::arg("uuid", uuid_str),
			fmt::arg("description", clock_class.description),
			fmt::arg("frequency", clock_class.frequency),
			fmt::arg("offset", clock_class.offset),
			fmt::arg("uint16_t_alignment", _trace_abi.uint16_t_alignment),
			fmt::arg("uint32_t_alignment", _trace_abi.uint32_t_alignment),
			fmt::arg("uint64_t_alignment", _trace_abi.uint64_t_alignment));

	append_metadata_fragment(std::move(clock_class_str));
}

void tsdl::trace_class_visitor::visit(const lttng::sessiond::trace::stream_class& stream_class)
{
	/* Declare stream. */
	auto stream_class_str = fmt::format("stream {{\n"
					    "	id = {id};\n"
					    "	event.header := {header_type};\n"
					    "	packet.context := struct packet_context;\n",
			fmt::arg("id", stream_class.id),
			fmt::arg("header_type", stream_class.header_type_ == lst::stream_class::header_type::COMPACT ?
							"struct event_header_compact" :
							      "struct event_header_large"));

	auto context_field_visitor = tsdl_field_visitor(_trace_abi, 1);

	stream_class.get_context().accept(static_cast<lst::type_visitor&>(context_field_visitor));

	stream_class_str += fmt::format("	event.context := {}\n}};\n\n",
			context_field_visitor.get_description());

	append_metadata_fragment(stream_class_str);
}

void tsdl::trace_class_visitor::visit(const lttng::sessiond::trace::event_class& event_class)
{
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
		event_class_str += fmt::format(
				"	model.emf.uri = \"{}\";\n", *event_class.model_emf_uri);
	}

	auto payload_visitor = tsdl_field_visitor(_trace_abi, 1);

	event_class.payload->accept(static_cast<lst::type_visitor&>(payload_visitor));

	event_class_str += fmt::format(
			"	fields := {}\n}};\n\n", payload_visitor.get_description());

	append_metadata_fragment(event_class_str);
}

void tsdl::trace_class_visitor::environment_begin()
{
	_environment += "env {\n";
}

void tsdl::trace_class_visitor::visit(
		const lttng::sessiond::trace::environment_field<int64_t>& field)
{
	_environment += fmt::format("	{} = {};\n", field.name, field.value);
}

void tsdl::trace_class_visitor::visit(
		const lttng::sessiond::trace::environment_field<const char *>& field)
{
	_environment += fmt::format(
			"	{} = \"{}\";\n", field.name, escape_tsdl_env_string_value(field.value));
}

void tsdl::trace_class_visitor::environment_end()
{
	_environment += "};\n\n";
	append_metadata_fragment(_environment);
	_environment.clear();
}
