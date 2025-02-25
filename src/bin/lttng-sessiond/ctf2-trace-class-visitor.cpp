/*
 * SPDX-FileCopyrightText: 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * SPDX-FileCopyrightText: 2022 Simon Marchi <simon.marchi@efficios.com>
 * SPDX-FileCopyrightText: 2025 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "bin/lttng-sessiond/field.hpp"
#include "clock-class.hpp"
#include "common/uuid.hpp"
#include "ctf2-trace-class-visitor.hpp"

#include <common/exception.hpp>
#include <common/format.hpp>

#include <vendor/nlohmann/json.hpp>

#include <utility>

namespace lttng {
namespace sessiond {

namespace nljson = nlohmann;

namespace {

nljson::json make_json_field_class(const char *const type,
				   nljson::json&& extra_json = nljson::json::object())
{
	extra_json["type"] = type;
	return extra_json;
}

nljson::json::object_t::value_type make_json_length_prop(const uint64_t length)
{
	return std::make_pair("length", length);
}

nljson::json json_fixed_length_bit_array_field_class_from_type(
	const char *const type_name,
	const trace::bit_array_type& type,
	nljson::json&& extra_json = nljson::json::object())
{
	extra_json.update({
		make_json_length_prop(type.size),
		{ "byte-order",
		  type.byte_order == trace::byte_order::BIG_ENDIAN_ ? "big-endian" :
								      "little-endian" },
		{ "alignment", type.alignment },
	});

	if (type.alignment > 0) {
		extra_json["alignment"] = type.alignment;
	}

	return make_json_field_class(type_name, std::move(extra_json));
}

const char *ctf_2_role_name(const trace::integer_type::role role) noexcept
{
	switch (role) {
	case trace::integer_type::role::DEFAULT_CLOCK_TIMESTAMP:
		return "default-clock-timestamp";
	case trace::integer_type::role::DATA_STREAM_CLASS_ID:
		return "data-stream-class-id";
	case trace::integer_type::role::DATA_STREAM_ID:
		return "data-stream-id";
	case trace::integer_type::role::PACKET_MAGIC_NUMBER:
		return "packet-magic-number";
	case trace::integer_type::role::DISCARDED_EVENT_RECORD_COUNTER_SNAPSHOT:
		return "discarded-event-record-counter-snapshot";
	case trace::integer_type::role::PACKET_CONTENT_LENGTH:
		return "packet-content-length";
	case trace::integer_type::role::PACKET_END_DEFAULT_CLOCK_TIMESTAMP:
		return "packet-end-default-clock-timestamp";
	case trace::integer_type::role::PACKET_SEQUENCE_NUMBER:
		return "packet-sequence-number";
	case trace::integer_type::role::PACKET_TOTAL_LENGTH:
		return "packet-total-length";
	case trace::integer_type::role::EVENT_RECORD_CLASS_ID:
		return "event-record-class-id";
	default:
		abort();
	}
}

nljson::json json_int_field_class_from_type(const trace::integer_type& int_type,
					    nljson::json&& extra_json = nljson::json::object())
{
	extra_json["preferred-display-base"] = static_cast<unsigned int>(int_type.base_);

	if (!int_type.roles_.empty()) {
		LTTNG_ASSERT(int_type.signedness_ == trace::integer_type::signedness::UNSIGNED);
		extra_json["roles"] = [&] {
			auto json_roles = nljson::json::array();

			for (const auto role : int_type.roles_) {
				json_roles.push_back(ctf_2_role_name(role));
			}

			return json_roles;
		}();
	}

	return json_fixed_length_bit_array_field_class_from_type(
		int_type.signedness_ == trace::integer_type::signedness::SIGNED ?
			"fixed-length-signed-integer" :
			"fixed-length-unsigned-integer",
		int_type,
		std::move(extra_json));
}

template <typename EnumerationType>
nljson::json json_int_field_class_from_type(const EnumerationType& int_type)
{
	return json_int_field_class_from_type(
		int_type, { { "mappings", [&] {
				     nljson::json json_mappings;

				     for (const auto& mapping : *int_type.mappings_) {
					     json_mappings[mapping.name] = {
						     { mapping.range.begin, mapping.range.end }
					     };
				     }

				     return json_mappings;
			     }() } });
}

nljson::json json_field_class_from_type(const trace::type& type);

template <typename ArrayType>
nljson::json::object_t::value_type
json_element_field_class_prop_from_array_type(const ArrayType& array_type)
{
	return std::make_pair("element-field-class",
			      json_field_class_from_type(*array_type.element_type));
}

nljson::json json_field_location_from_obj(const trace::field_location& location)
{
	return {
		{ "origin",
		  [&] {
			  switch (location.root_) {
			  case trace::field_location::root::PACKET_HEADER:
				  return "packet-header";
			  case trace::field_location::root::PACKET_CONTEXT:
				  return "packet-context";
			  case trace::field_location::root::EVENT_RECORD_HEADER:
				  return "event-record-header";
			  case trace::field_location::root::EVENT_RECORD_COMMON_CONTEXT:
				  return "event-record-common-context";
			  case trace::field_location::root::EVENT_RECORD_SPECIFIC_CONTEXT:
				  return "event-record-specific-context";
			  case trace::field_location::root::EVENT_RECORD_PAYLOAD:
				  return "event-record-payload";
			  default:
				  abort();
			  }
		  }() },
		{ "path",
		  [&] {
			  nljson::json location_array;

			  for (auto& elem : location.elements_) {
				  location_array.emplace_back(elem);
			  }

			  return location_array;
		  }() },
	};
}

template <typename Type>
std::pair<std::string, nljson::json> json_length_field_location_prop_from_type(const Type& type)
{
	return std::make_pair("length-field-location",
			      json_field_location_from_obj(type.length_field_location));
}

template <typename Type>
void add_minimum_alignment_prop_to_json_field_class_from_type(nljson::json& json_field_class,
							      const Type& type)
{
	if (type.alignment == 0) {
		return;
	}

	json_field_class["minimum-alignment"] = type.alignment;
}

nljson::json::object_t::value_type make_json_name_prop(std::string name)
{
	return std::make_pair("name", std::move(name));
}

nljson::json::object_t::value_type make_json_field_class_prop(const trace::type& type)
{
	return std::make_pair("field-class", json_field_class_from_type(type));
}

class type_visitor final : public trace::type_visitor {
public:
	/* Only call once. */
	nljson::json release_json_field_class()
	{
		return std::move(_json_field_class);
	}

private:
	void visit(const trace::bit_array_type& type) override
	{
		_json_field_class = json_fixed_length_bit_array_field_class_from_type(
			"fixed-length-bit-array", type);
	}

	void visit(const trace::integer_type& type) override
	{
		_json_field_class = json_int_field_class_from_type(type);
	}

	void visit(const trace::floating_point_type& type) override
	{
		_json_field_class = json_fixed_length_bit_array_field_class_from_type(
			"fixed-length-floating-point-number", type);
	}

	void visit(const trace::signed_enumeration_type& type) override
	{
		_json_field_class = json_int_field_class_from_type(type);
	}

	void visit(const trace::unsigned_enumeration_type& type) override
	{
		_json_field_class = json_int_field_class_from_type(type);
	}

	void visit(const trace::static_length_array_type& type) override
	{
		_json_field_class = make_json_field_class("static-length-array", [&] {
			nljson::json json_field_class{
				json_element_field_class_prop_from_array_type(type),
				make_json_length_prop(type.length),
			};

			add_minimum_alignment_prop_to_json_field_class_from_type(json_field_class,
										 type);

			return json_field_class;
		}());
	}

	void visit(const trace::dynamic_length_array_type& type) override
	{
		_json_field_class = make_json_field_class("dynamic-length-array", [&] {
			nljson::json json_field_class{
				json_element_field_class_prop_from_array_type(type),
				json_length_field_location_prop_from_type(type),
			};

			add_minimum_alignment_prop_to_json_field_class_from_type(json_field_class,
										 type);

			return json_field_class;
		}());
	}

	void visit(const trace::static_length_blob_type& type) override
	{
		_json_field_class = make_json_field_class("static-length-blob", [&] {
			nljson::json json_field_class{
				make_json_length_prop(type.length_bytes),
			};

			if (!type.roles_.empty()) {
				LTTNG_ASSERT(type.roles_.size() == 1);
				LTTNG_ASSERT(
					type.roles_.front() ==
					trace::static_length_blob_type::role::METADATA_STREAM_UUID);
				json_field_class["roles"] = { "metadata-stream-uuid" };
			}

			return json_field_class;
		}());
	}

	void visit(const trace::dynamic_length_blob_type& type) override
	{
		_json_field_class = make_json_field_class(
			"dynamic-length-blob",
			{
				json_length_field_location_prop_from_type(type),
			});
	}

	void visit(const trace::null_terminated_string_type&) override
	{
		_json_field_class = make_json_field_class("null-terminated-string");
	}

	void visit(const trace::structure_type& type) override
	{
		_json_field_class = make_json_field_class("structure", [&] {
			nljson::json json_field_class{
				{ "member-classes",
				  [&] {
					  auto json_member_classes = nljson::json::array();

					  for (auto& field : type.fields_) {
						  json_member_classes.emplace_back(nljson::json{
							  make_json_name_prop(field->name),
							  make_json_field_class_prop(
								  field->get_type()),
						  });
					  }

					  return json_member_classes;
				  }() }
			};

			add_minimum_alignment_prop_to_json_field_class_from_type(json_field_class,
										 type);
			return json_field_class;
		}());
	}

	template <class MappingIntegerType>
	void _visit_variant(const trace::variant_type<MappingIntegerType>& type)
	{
		_json_field_class = make_json_field_class(
			"variant",
			{
				{ "selector-field-location",
				  json_field_location_from_obj(type.selector_field_location) },
				{ "options",
				  [&] {
					  auto json_options = nljson::json::array();

					  for (auto& choice : type.choices_) {
						  json_options.emplace_back(nljson::json{
							  make_json_name_prop(choice.first.name),
							  make_json_field_class_prop(*choice.second),
							  { "selector-field-ranges",
							    { { choice.first.range.begin,
								choice.first.range.end } } },
						  });
					  }

					  return json_options;
				  }() },
			});
	}

	void visit(const trace::variant_type<int64_t>& type) override
	{
		_visit_variant(type);
	}

	void visit(const trace::variant_type<uint64_t>& type) override
	{
		_visit_variant(type);
	}

	void visit(const trace::static_length_string_type& type) override
	{
		_json_field_class = make_json_field_class("static-length-string",
							  { make_json_length_prop(type.length) });
	}

	void visit(const trace::dynamic_length_string_type& type) override
	{
		_json_field_class = make_json_field_class(
			"dynamic-length-string",
			{
				json_length_field_location_prop_from_type(type),
			});
	}

	nljson::json _json_field_class;
};

nljson::json json_field_class_from_type(const trace::type& type)
{
	type_visitor visitor;

	type.accept(visitor);
	return visitor.release_json_field_class();
}

void add_scope_field_class_prop_to_json_fragment_from_type(nljson::json& json_fragment,
							   const char *const name,
							   const trace::type *const type)
{
	if (!type) {
		return;
	}

	json_fragment[name] = json_field_class_from_type(*type);
}

} /* namespace */

namespace ctf2 {

trace_class_visitor::trace_class_visitor(
	append_metadata_fragment_function append_metadata_fragment) :
	_append_metadata_fragment_func(std::move(append_metadata_fragment))
{
}

void trace_class_visitor::_append_metadata_fragment(const char *const type,
						    nlohmann::json&& extra_json) const
{
	_append_metadata_fragment_func(std::string("\x1e") +
				       [&] {
					       extra_json["type"] = type;
					       return extra_json;
				       }()
					       .dump(2)
					       .c_str());
}

namespace {

class trace_environment_visitor final : public trace::trace_class_environment_visitor {
public:
	/* Only call once. */
	nljson::json release_json_environment()
	{
		return std::move(_json_env);
	}

private:
	void visit(const trace::environment_field<int64_t>& field) override
	{
		_visit(field);
	}

	void visit(const trace::environment_field<const char *>& field) override
	{
		_visit(field);
	}

	template <typename FieldType>
	void _visit(const FieldType& field)
	{
		_json_env[field.name] = field.value;
	}

	nljson::json _json_env;
};

template <typename IdType>
nljson::json::object_t::value_type make_json_id_prop(IdType&& id)
{
	return std::make_pair("id", std::forward<IdType>(id));
}

const char *const ctf_2_lttng_ns = "lttng.org,2009";

nljson::json::object_t::value_type make_json_ns_prop()
{
	return std::make_pair("namespace", ctf_2_lttng_ns);
}

nljson::json::object_t::value_type make_json_uid_prop(const lttng_uuid& uuid)
{
	return std::make_pair("uid", lttng::utils::uuid_to_str(uuid));
}

} /* namespace */

void trace_class_visitor::visit(const trace::trace_class& trace_class)
{
	_append_metadata_fragment("preamble",
				  {
					  { "version", 2 },
					  { "uuid", trace_class.uuid },
				  });

	_append_metadata_fragment("trace-class", [&] {
		nljson::json json_fragment{
			{ "environment",
			  [&] {
				  trace_environment_visitor environment_visitor;

				  trace_class.accept(environment_visitor);
				  return environment_visitor.release_json_environment();
			  }() },
			make_json_ns_prop(),
			make_json_name_prop(""),
			make_json_uid_prop(trace_class.uuid),
		};

		add_scope_field_class_prop_to_json_fragment_from_type(
			json_fragment, "packet-header-field-class", trace_class.packet_header());
		return json_fragment;
	}());
}

void trace_class_visitor::visit(const trace::clock_class& clock_class)
{
	_append_metadata_fragment("clock-class", [&] {
		nljson::json json_fragment{
			make_json_id_prop(clock_class.name),
			make_json_name_prop(clock_class.name),
			{ "description", clock_class.description },
			{ "frequency", clock_class.frequency },
			{ "origin", "unix-epoch" },
			{ "offset-from-origin",
			  { { "seconds", clock_class.offset / clock_class.frequency },
			    { "cycles", clock_class.offset % clock_class.frequency } } },
		};

		if (clock_class.uuid) {
			json_fragment["uid"] = lttng::utils::uuid_to_str(*clock_class.uuid);
		}

		return json_fragment;
	}());
}

void trace_class_visitor::visit(const trace::stream_class& stream_class)
{
	return _append_metadata_fragment("data-stream-class", [&] {
		nljson::json json_fragment{
			make_json_id_prop(stream_class.id),
		};

		if (stream_class.default_clock_class_name) {
			json_fragment["default-clock-class-id"] =
				*stream_class.default_clock_class_name;
		}

		add_scope_field_class_prop_to_json_fragment_from_type(
			json_fragment, "packet-context-field-class", stream_class.packet_context());
		add_scope_field_class_prop_to_json_fragment_from_type(
			json_fragment,
			"event-record-header-field-class",
			stream_class.event_header());
		add_scope_field_class_prop_to_json_fragment_from_type(
			json_fragment,
			"event-record-common-context-field-class",
			stream_class.event_context());
		return json_fragment;
	}());
}

void trace_class_visitor::visit(const trace::event_class& event_class)
{
	return _append_metadata_fragment("event-record-class", [&] {
		nljson::json json_fragment{
			make_json_id_prop(event_class.id),
			{ "data-stream-class-id", event_class.stream_class_id },
			make_json_name_prop(event_class.name),
		};

		add_scope_field_class_prop_to_json_fragment_from_type(
			json_fragment, "payload-field-class", event_class.payload.get());

		if (event_class.model_emf_uri || event_class.log_level <= 14) {
			json_fragment["attributes"][ctf_2_lttng_ns] = [&] {
				nljson::json json_attr;

				if (event_class.model_emf_uri) {
					json_attr["emf-uri"] = *event_class.model_emf_uri;
				}

				if (event_class.log_level <= 14) {
					json_attr["log-level"] = [&] {
						switch (event_class.log_level) {
						case 0:
							return "emergency";
						case 1:
							return "alert";
						case 2:
							return "critical";
						case 3:
							return "error";
						case 4:
							return "warning";
						case 5:
							return "notice";
						case 6:
							return "info";
						case 7:
							return "debug:system";
						case 8:
							return "debug:program";
						case 9:
							return "debug:process";
						case 10:
							return "debug:module";
						case 11:
							return "debug:unit";
						case 12:
							return "debug:function";
						case 13:
							return "debug:line";
						case 14:
							return "debug";
						default:
							abort();
						}
					}();
				}

				return json_attr;
			}();
		}

		return json_fragment;
	}());
}

} /* namespace ctf2 */
} /* namespace sessiond */
} /* namespace lttng */
