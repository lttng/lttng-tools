/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * Copyright (C) 2022 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "clock-class.hpp"
#include "ctf2-trace-class-visitor.hpp"

#include <common/exception.hpp>
#include <common/format.hpp>

#include <vendor/nlohmann/json.hpp>

#include <algorithm>
#include <utility>

namespace lsc = lttng::sessiond::ctf2;
namespace lst = lttng::sessiond::trace;

namespace json = nlohmann;

namespace {
const unsigned int spaces_per_indent = 2;
const std::string record_separator = "\x1e";

json::json make_json_fragment(const char *type)
{
	return { { "type", type } };
}

json::json to_json(const lst::field_location& location)
{
	json::json location_array;

	switch (location.root_) {
	case lst::field_location::root::PACKET_HEADER:
		location_array.push_back("packet-header");
		break;
	case lst::field_location::root::PACKET_CONTEXT:
		location_array.push_back("packet-context");
		break;
	case lst::field_location::root::EVENT_RECORD_HEADER:
		location_array.push_back("event-record-header");
		break;
	case lst::field_location::root::EVENT_RECORD_COMMON_CONTEXT:
		location_array.push_back("event-record-common-context");
		break;
	case lst::field_location::root::EVENT_RECORD_SPECIFIC_CONTEXT:
		location_array.push_back("event-record-specific-context");
		break;
	case lst::field_location::root::EVENT_RECORD_PAYLOAD:
		location_array.push_back("event-record-payload");
		break;
	}

	std::copy(location.elements_.begin(),
		  location.elements_.end(),
		  std::back_inserter(location_array));
	return location_array;
}

const char *get_role_name(lst::integer_type::role role)
{
	switch (role) {
	case lst::integer_type::role::DEFAULT_CLOCK_TIMESTAMP:
		return "default-clock-timestamp";
	case lst::integer_type::role::DATA_STREAM_CLASS_ID:
		return "data-stream-class-id";
	case lst::integer_type::role::DATA_STREAM_ID:
		return "data-stream-id";
	case lst::integer_type::role::PACKET_MAGIC_NUMBER:
		return "packet-magic-number";
	case lst::integer_type::role::DISCARDED_EVENT_RECORD_COUNTER_SNAPSHOT:
		return "discarded-event-record-counter-snapshot";
	case lst::integer_type::role::PACKET_CONTENT_LENGTH:
		return "packet-content-length";
	case lst::integer_type::role::PACKET_END_DEFAULT_CLOCK_TIMESTAMP:
		return "packet-end-default-clock-timestamp";
	case lst::integer_type::role::PACKET_SEQUENCE_NUMBER:
		return "packet-sequence-number";
	case lst::integer_type::role::PACKET_TOTAL_LENGTH:
		return "packet-total-length";
	case lst::integer_type::role::EVENT_RECORD_CLASS_ID:
		return "event-record-class-id";
	default:
		abort();
	}
}

const char *get_role_name(lst::static_length_blob_type::role role)
{
	switch (role) {
	case lst::static_length_blob_type::role::METADATA_STREAM_UUID:
		return "metadata-stream-uuid";
	default:
		abort();
	}
}

namespace ctf2 {
class trace_environment_visitor : public lst::trace_class_environment_visitor {
public:
	trace_environment_visitor() = default; /* NOLINT clang-tidy 14 identifies this as a move
						  constructor. */

	void visit(const lst::environment_field<int64_t>& field) override
	{
		_visit(field);
	}

	void visit(const lst::environment_field<const char *>& field) override
	{
		_visit(field);
	}

	/* Only call once. */
	json::json move_fragment()
	{
		return std::move(_environment);
	}

private:
	template <class FieldType>
	void _visit(const FieldType& field)
	{
		_environment[field.name] = field.value;
	}

	json::json _environment;
};

class field_visitor : public lttng::sessiond::trace::field_visitor,
		      public lttng::sessiond::trace::type_visitor {
public:
	field_visitor() = default; /* NOLINT clang-tidy 14 identifies this as a move constructor. */

	/* Only call once. */
	json::json move_fragment()
	{
		return std::move(_fragment);
	}

private:
	void visit(const lst::field& field) final
	{
		field_visitor field_type_visitor;
		field.get_type().accept(field_type_visitor);

		_fragment["name"] = field.name;
		_fragment["field-class"] = field_type_visitor.move_fragment();
	}

	void visit(const lst::integer_type& type) final
	{
		_fragment["type"] = type.signedness_ == lst::integer_type::signedness::SIGNED ?
			"fixed-length-signed-integer" :
			"fixed-length-unsigned-integer";
		_fragment["length"] = type.size;
		_fragment["byte-order"] = type.byte_order == lst::byte_order::BIG_ENDIAN_ ?
			"big-endian" :
			"little-endian";
		_fragment["alignment"] = type.alignment;
		_fragment["preferred-display-base"] = (unsigned int) type.base_;

		if (type.roles_.size() > 0) {
			json::json role_array = json::json::array();

			for (const auto role : type.roles_) {
				role_array.push_back(get_role_name(role));
			}

			_fragment["roles"] = std::move(role_array);
		}
	}

	void visit(const lst::floating_point_type& type) final
	{
		_fragment["type"] = "fixed-length-floating-point-number";
		_fragment["length"] = type.exponent_digits + type.mantissa_digits;
		_fragment["byte-order"] = type.byte_order == lst::byte_order::BIG_ENDIAN_ ?
			"big-endian" :
			"little-endian";
		_fragment["alignment"] = type.alignment;
	}

	template <class EnumerationType>
	void visit_enumeration(const EnumerationType& type)
	{
		_fragment["type"] =
			std::is_signed<
				typename EnumerationType::mapping::range_t::range_integer_t>::value ?
			"fixed-length-signed-enumeration" :
			"fixed-length-unsigned-enumeration";
		_fragment["length"] = type.size;
		_fragment["byte-order"] = type.byte_order == lst::byte_order::BIG_ENDIAN_ ?
			"big-endian" :
			"little-endian";
		_fragment["alignment"] = type.alignment;
		_fragment["preferred-display-base"] = (unsigned int) type.base_;

		if (type.roles_.size() > 0) {
			if (std::is_signed<typename EnumerationType::mapping::range_t::
						   range_integer_t>::value) {
				LTTNG_THROW_ERROR(
					lttng::format("Failed to serialize {}: unexpected role",
						      _fragment["type"]));
			}

			auto role_array = json::json::array();

			for (const auto role : type.roles_) {
				role_array.push_back(get_role_name(role));
			}

			_fragment["roles"] = std::move(role_array);
		}

		if (type.mappings_->size() < 1) {
			LTTNG_THROW_ERROR(lttng::format(
				"Failed to serialize {}: enumeration must have at least one mapping",
				_fragment["type"]));
		}

		json::json mappings_value;
		for (const auto& mapping : *type.mappings_) {
			mappings_value[mapping.name] = { { mapping.range.begin,
							   mapping.range.end } };
		}

		_fragment["mappings"] = std::move(mappings_value);
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
		_fragment["type"] = "static-length-array";

		::ctf2::field_visitor element_visitor;
		type.element_type->accept(element_visitor);
		_fragment["element-field-class"] = element_visitor.move_fragment();

		if (type.alignment != 0) {
			_fragment["minimum-alignment"] = type.alignment;
		}

		_fragment["length"] = type.length;
	}

	void visit(const lst::dynamic_length_array_type& type) final
	{
		_fragment["type"] = "dynamic-length-array";

		::ctf2::field_visitor element_visitor;
		type.element_type->accept(element_visitor);
		_fragment["element-field-class"] = element_visitor.move_fragment();

		if (type.alignment != 0) {
			_fragment["minimum-alignment"] = type.alignment;
		}

		_fragment["length-field-location"] = to_json(type.length_field_location);
	}

	void visit(const lst::static_length_blob_type& type) final
	{
		_fragment["type"] = "static-length-blob";
		_fragment["length"] = type.length_bytes;

		if (type.roles_.size() > 0) {
			auto role_array = json::json::array();

			for (const auto role : type.roles_) {
				role_array.push_back(get_role_name(role));
			}

			_fragment["roles"] = std::move(role_array);
		}
	}

	void visit(const lst::dynamic_length_blob_type& type) final
	{
		_fragment["type"] = "dynamic-length-blob";
		_fragment["length-field-location"] = to_json(type.length_field_location);
	}

	void visit(const lst::null_terminated_string_type& type __attribute__((unused))) final
	{
		_fragment["type"] = "null-terminated-string";
	}

	void visit(const lst::structure_type& type) final
	{
		_fragment["type"] = "structure";

		if (type.alignment != 0) {
			_fragment["minimum-alignment"] = type.alignment;
		}

		auto member_classes_value = json::json::array();
		for (const auto& field : type.fields_) {
			::ctf2::field_visitor member_visitor;
			json::json member_class;

			field->accept(member_visitor);
			member_classes_value.emplace_back(member_visitor.move_fragment());
		}

		_fragment["member-classes"] = std::move(member_classes_value);
	}

	template <class MappingIntegerType>
	void visit_variant(const lst::variant_type<MappingIntegerType>& type)
	{
		_fragment["type"] = "variant";
		_fragment["selector-field-location"] = to_json(type.selector_field_location);

		auto options_value = json::json::array();
		for (const auto& option : type.choices_) {
			::ctf2::field_visitor option_visitor;
			json::json member_class;

			/* TODO missing selector-field-range. */
			member_class["selector-field-ranges"] = { { option.first.range.begin,
								    option.first.range.end } };
			option.second->accept(option_visitor);
			member_class["field-class"] = option_visitor.move_fragment();
			options_value.emplace_back(std::move(member_class));
		}

		_fragment["options"] = std::move(options_value);
	}

	void visit(const lst::variant_type<int64_t>& type) final
	{
		visit_variant(type);
	}

	void visit(const lst::variant_type<uint64_t>& type) final
	{
		visit_variant(type);
	}

	void visit(const lst::static_length_string_type& type) final
	{
		_fragment["type"] = "static-length-string";
		_fragment["length"] = type.length;
	}

	void visit(const lst::dynamic_length_string_type& type) final
	{
		_fragment["type"] = "dynamic-length-string";
		_fragment["length-field-location"] = to_json(type.length_field_location);
	}

	json::json _fragment;
};
} /* namespace ctf2 */

}; /* namespace */

lsc::trace_class_visitor::trace_class_visitor(
	lsc::append_metadata_fragment_function append_metadata_fragment) :
	_append_metadata_fragment(std::move(append_metadata_fragment))
{
}

void lsc::trace_class_visitor::visit(const lst::trace_class& trace_class)
{
	{
		auto preamble_fragment = make_json_fragment("preamble");

		preamble_fragment["version"] = 2;
		preamble_fragment["uuid"] = trace_class.uuid;
		append_metadata_fragment(preamble_fragment);
	}

	auto trace_class_fragment = make_json_fragment("trace-class");

	::ctf2::trace_environment_visitor environment_visitor;
	trace_class.accept(environment_visitor);
	trace_class_fragment["environment"] = environment_visitor.move_fragment();

	const auto packet_header = trace_class.packet_header();
	if (packet_header) {
		::ctf2::field_visitor field_visitor;

		packet_header->accept(field_visitor);
		trace_class_fragment["packet-header-field-class"] = field_visitor.move_fragment();
	}

	append_metadata_fragment(trace_class_fragment);
}

void lsc::trace_class_visitor::visit(const lst::clock_class& clock_class)
{
	auto clock_class_fragment = make_json_fragment("clock-class");

	json::json offset;
	offset.update({ { "seconds", clock_class.offset / clock_class.frequency },
			{ "cycles", clock_class.offset % clock_class.frequency } });

	clock_class_fragment.update({ { "name", clock_class.name },
				      { "description", clock_class.description },
				      { "frequency", clock_class.frequency },
				      { "offset", std::move(offset) } });

	if (clock_class.uuid) {
		clock_class_fragment["uuid"] = *clock_class.uuid;
	}

	append_metadata_fragment(clock_class_fragment);
}

void lsc::trace_class_visitor::visit(const lst::stream_class& stream_class)
{
	auto stream_class_fragment = make_json_fragment("data-stream-class");

	stream_class_fragment["id"] = stream_class.id;
	if (stream_class.default_clock_class_name) {
		stream_class_fragment["default-clock-class-name"] =
			*stream_class.default_clock_class_name;
	}

	const auto packet_context = stream_class.packet_context();
	if (packet_context) {
		::ctf2::field_visitor visitor;

		packet_context->accept(visitor);
		stream_class_fragment["packet-context-field-class"] = visitor.move_fragment();
	}

	const auto event_header = stream_class.event_header();
	if (event_header) {
		::ctf2::field_visitor visitor;

		event_header->accept(visitor);
		stream_class_fragment["event-record-header-field-class"] = visitor.move_fragment();
	}

	const auto event_context = stream_class.event_context();
	if (event_context) {
		::ctf2::field_visitor visitor;

		event_context->accept(visitor);
		stream_class_fragment["event-record-common-context-field-class"] =
			visitor.move_fragment();
	}

	append_metadata_fragment(stream_class_fragment);
}

void lsc::trace_class_visitor::visit(const lst::event_class& event_class)
{
	auto event_class_fragment = make_json_fragment("event-record-class");

	event_class_fragment["id"] = event_class.id;
	event_class_fragment["data-stream-class-id"] = event_class.stream_class_id;
	event_class_fragment["name"] = event_class.name;

	if (event_class.payload) {
		::ctf2::field_visitor visitor;

		event_class.payload->accept(visitor);
		event_class_fragment["payload-field-class"] = visitor.move_fragment();
	}

	append_metadata_fragment(event_class_fragment);
}

void lsc::trace_class_visitor::append_metadata_fragment(const nlohmann::json& fragment) const
{
	_append_metadata_fragment(record_separator + fragment.dump(spaces_per_indent).c_str());
}
