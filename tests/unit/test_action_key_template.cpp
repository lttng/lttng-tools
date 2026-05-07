/*
 * Unit tests for the key-template trigger action utility.
 *
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <common/error.hpp>
#include <common/make-unique.hpp>
#include <common/payload-view.hpp>
#include <common/payload.hpp>

#include <lttng/action/key-template-internal.hpp>
#include <lttng/action/key-template.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <memory>
#include <string>
#include <sys/types.h>
#include <tap/tap.h>
#include <utility>
#include <vector>

/* For error.h */
bool lttng_opt_is_tui = true;
int lttng_opt_quiet = 1;
int lttng_opt_verbose;
int lttng_opt_mi;

namespace details = lttng::action::details;

namespace {

constexpr unsigned int NUM_VALID_CASES = 12;
constexpr unsigned int NUM_INVALID_CASES = 10;
constexpr unsigned int NUM_SERIALIZE_CASES = 3;
constexpr unsigned int NUM_TESTS =
	NUM_VALID_CASES * 4 + NUM_INVALID_CASES + 4 + 3 + NUM_SERIALIZE_CASES * 3;

struct expected_segment {
	details::key_template_segment_type type;
	/* Only meaningful for `LITERAL` segments. */
	std::string literal;
};

expected_segment make_literal(std::string text)
{
	return expected_segment{ details::key_template_segment_type::LITERAL, std::move(text) };
}

expected_segment make_event_name()
{
	return expected_segment{ details::key_template_segment_type::EVENT_NAME, {} };
}

expected_segment make_provider_name()
{
	return expected_segment{ details::key_template_segment_type::PROVIDER_NAME, {} };
}

bool segments_match(const lttng_key_template& tmpl,
		    const std::vector<expected_segment>& expected) noexcept
{
	if (tmpl.segments.size() != expected.size()) {
		return false;
	}

	return std::equal(tmpl.segments.begin(),
			  tmpl.segments.end(),
			  expected.begin(),
			  [](const std::unique_ptr<details::key_template_segment>& actual,
			     const expected_segment& exp) noexcept {
				  if (actual->type != exp.type) {
					  return false;
				  }

				  if (actual->type != details::key_template_segment_type::LITERAL) {
					  return true;
				  }

				  const auto& literal =
					  static_cast<const details::key_template_literal_segment&>(
						  *actual);

				  return literal.text == exp.literal;
			  });
}

struct round_trip_case {
	const char *input;
	std::vector<expected_segment> segments;
};

/*
 * For each entry, parse the input string and check that:
 *
 *   - parsing succeeds;
 *   - the resulting segment list matches `segments` exactly (verifies how the
 *     parser cuts the input);
 *   - rendering it reproduces `input` verbatim (verifies escape generation);
 *   - re-parsing the rendered form produces a template equal to the first
 *     parse (verifies parse/render idempotency).
 *
 * The parser does not normalize anything it accepts (no whitespace handling,
 * no placeholder aliases, strict 1:1 escapes), so any input it accepts is
 * already its own canonical form -- hence a single string per case.
 */
void test_round_trip_and_segments()
{
	const std::vector<round_trip_case> cases = {
		{ "foo", { make_literal("foo") } },
		{ "foo.bar", { make_literal("foo.bar") } },
		{ "{event_name}", { make_event_name() } },
		{ "{provider_name}", { make_provider_name() } },
		{ "pre-{event_name}-post",
		  { make_literal("pre-"), make_event_name(), make_literal("-post") } },
		{ "{provider_name}:{event_name}",
		  { make_provider_name(), make_literal(":"), make_event_name() } },
		{ "{event_name}{provider_name}", { make_event_name(), make_provider_name() } },
		{ "{{", { make_literal("{") } },
		{ "}}", { make_literal("}") } },
		{ "{{}}", { make_literal("{}") } },
		{ "a{{b}}c", { make_literal("a{b}c") } },
		{ "lit-{{-{event_name}-}}-end",
		  { make_literal("lit-{-"), make_event_name(), make_literal("-}-end") } },
	};

	LTTNG_ASSERT(cases.size() == NUM_VALID_CASES);

	for (const auto& test_case : cases) {
		diag("Round-trip case: input=`%s`", test_case.input);

		struct lttng_key_template *const parsed =
			lttng_key_template_create_from_string(test_case.input);

		ok(parsed != nullptr, "Parse of `%s` succeeds", test_case.input);

		ok(parsed != nullptr && segments_match(*parsed, test_case.segments),
		   "Parsed segments of `%s` match the expected layout",
		   test_case.input);

		char *rendered = nullptr;
		const auto status = parsed ? lttng_key_template_to_string(parsed, &rendered) :
					     LTTNG_KEY_TEMPLATE_STATUS_ERROR;

		ok(status == LTTNG_KEY_TEMPLATE_STATUS_OK && rendered != nullptr &&
			   std::strcmp(rendered, test_case.input) == 0,
		   "Rendered form of `%s` matches its input",
		   test_case.input);

		struct lttng_key_template *const reparsed =
			rendered ? lttng_key_template_create_from_string(rendered) : nullptr;

		ok(parsed != nullptr && reparsed != nullptr && *parsed == *reparsed,
		   "Re-parsing the rendered form of `%s` yields an equal template",
		   test_case.input);

		std::free(rendered);
		lttng_key_template_destroy(parsed);
		lttng_key_template_destroy(reparsed);
	}
}

/*
 * Each entry must be rejected by the parser. The second member is a
 * human-readable explanation used in the test description.
 */
void test_invalid_inputs()
{
	const std::vector<std::pair<const char *, const char *>> cases = {
		{ "{", "trailing open brace" },
		{ "}", "lone close brace" },
		{ "{event_name", "unterminated placeholder" },
		{ "{}", "empty placeholder name" },
		{ "{unknown}", "unknown placeholder name" },
		{ "{event_name{nested}", "nested open brace inside placeholder" },
		{ "abc{", "trailing open brace after literal" },
		{ "abc}", "lone close brace after literal" },
		{ "}}}", "odd run of close braces" },
		{ "{event_name}{", "trailing open brace after placeholder" },
	};

	LTTNG_ASSERT(cases.size() == NUM_INVALID_CASES);

	for (const auto& test_case : cases) {
		struct lttng_key_template *const parsed =
			lttng_key_template_create_from_string(test_case.first);

		ok(parsed == nullptr, "Parser rejects `%s` (%s)", test_case.first, test_case.second);
		lttng_key_template_destroy(parsed);
	}
}

void test_api_preconditions()
{
	ok(lttng_key_template_create_from_string(nullptr) == nullptr,
	   "Parsing a NULL string returns NULL");
	ok(lttng_key_template_create_from_string("") == nullptr,
	   "Parsing an empty string returns NULL");

	char *out = nullptr;
	ok(lttng_key_template_to_string(nullptr, &out) == LTTNG_KEY_TEMPLATE_STATUS_INVALID,
	   "Rendering a NULL template returns INVALID");

	struct lttng_key_template *const tmpl =
		lttng_key_template_create_from_string("{event_name}");

	LTTNG_ASSERT(tmpl);
	ok(lttng_key_template_to_string(tmpl, nullptr) == LTTNG_KEY_TEMPLATE_STATUS_INVALID,
	   "Rendering with a NULL output pointer returns INVALID");
	lttng_key_template_destroy(tmpl);
}

void test_equality_and_copy()
{
	struct lttng_key_template *const a =
		lttng_key_template_create_from_string("pre-{event_name}");
	struct lttng_key_template *const b =
		lttng_key_template_create_from_string("pre-{event_name}");
	struct lttng_key_template *const c =
		lttng_key_template_create_from_string("pre-{provider_name}");

	LTTNG_ASSERT(a && b && c);

	ok(*a == *b, "Two templates parsed from the same string compare equal");
	ok(*a != *c, "Two templates parsed from different strings compare unequal");

	{
		const auto copy = lttng::make_unique<lttng_key_template>(*a);

		ok(*copy == *a, "Deep copy of a template compares equal to the original");
	}

	lttng_key_template_destroy(a);
	lttng_key_template_destroy(b);
	lttng_key_template_destroy(c);
}

void test_serialize_round_trip()
{
	const std::vector<const char *> cases = {
		"foo",
		"{event_name}",
		"x-{event_name}-{provider_name}-{{end}}",
	};

	LTTNG_ASSERT(cases.size() == NUM_SERIALIZE_CASES);

	for (const auto *input : cases) {
		diag("Serialize round-trip case: input=`%s`", input);

		struct lttng_key_template *const original =
			lttng_key_template_create_from_string(input);

		LTTNG_ASSERT(original);

		struct lttng_payload payload;

		lttng_payload_init(&payload);

		const int serialize_ret = original->serialize(payload);

		ok(serialize_ret == 0, "Serialize template `%s` succeeds", input);

		std::unique_ptr<lttng_key_template> restored;
		ssize_t consumed_len = -1;

		{
			lttng_payload_view view = lttng_payload_view_from_payload(&payload, 0, -1);

			consumed_len = lttng_key_template::create_from_payload(view, restored);
		}

		ok(consumed_len > 0 && restored != nullptr,
		   "Deserialize template `%s` yields a non-null template",
		   input);

		ok(restored != nullptr && *restored == *original,
		   "Round-tripped template `%s` is equal to the original",
		   input);

		lttng_payload_reset(&payload);
		lttng_key_template_destroy(original);
	}
}

int _main()
{
	plan_tests(NUM_TESTS);
	test_round_trip_and_segments();
	test_invalid_inputs();
	test_api_preconditions();
	test_equality_and_copy();
	test_serialize_round_trip();

	return exit_status();
}

} /* namespace */

int main()
{
	try {
		return _main();
	} catch (const std::exception& e) {
		ERR_FMT("Unhandled exception caught by key-template unit test: {}", e.what());
		abort();
	}
}
