/*
 * SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/make-unique.hpp>
#include <common/table-writer.hpp>

#include <cstdint>
#include <sstream>
#include <string>
#include <tap/tap.h>
#include <utility>
#include <vector>

bool lttng_opt_is_tui = false;
int lttng_opt_quiet = 1;
int lttng_opt_verbose;
int lttng_opt_mi;

namespace {

namespace tw = lttng::tw;

/*
 * Builds a left-aligned, non-wrappable string column descriptor
 * unless overridden.
 */
tw::table_col_descr::uptr
make_str_col_descr(const char *const header,
		   const tw::table_cell_align align = tw::table_cell_align::LEFT,
		   const bool is_wrappable = false)
{
	return lttng::make_unique<tw::table_str_col_descr>(header, align, is_wrappable);
}

/*
 * Builds a signed integer column descriptor.
 */
tw::table_col_descr::uptr make_int_col_descr(const char *const header)
{
	return lttng::make_unique<tw::table_signed_int_col_descr>(header);
}

/*
 * Builds an `lttng::bigint` column descriptor.
 */
tw::table_col_descr::uptr make_bigint_col_descr(const char *const header)
{
	return lttng::make_unique<tw::table_bigint_col_descr>(header);
}

/*
 * Collects a variadic list of cell pointers into a row vector.
 */
void push_cells(std::vector<tw::table_cell::uptr>&)
{
}

template <typename... RestTypes>
void push_cells(std::vector<tw::table_cell::uptr>& row,
		tw::table_cell::uptr first,
		RestTypes... rest)
{
	row.push_back(std::move(first));
	push_cells(row, std::move(rest)...);
}

template <typename... CellTypes>
std::vector<tw::table_cell::uptr> row(CellTypes... cells)
{
	std::vector<tw::table_cell::uptr> result;

	push_cells(result, std::move(cells)...);
	return result;
}

/*
 * Collects a variadic list of column descriptors into a schema vector.
 */
void push_cols(std::vector<tw::table_col_descr::uptr>&)
{
}

template <typename... RestTypes>
void push_cols(std::vector<tw::table_col_descr::uptr>& cols,
	       tw::table_col_descr::uptr first,
	       RestTypes... rest)
{
	cols.push_back(std::move(first));
	push_cols(cols, std::move(rest)...);
}

template <typename... ColTypes>
std::vector<tw::table_col_descr::uptr> cols(ColTypes... col_descrs)
{
	std::vector<tw::table_col_descr::uptr> result;

	push_cols(result, std::move(col_descrs)...);
	return result;
}

/*
 * Renders `writer` within `max_width` and checks that the result is
 * exactly `expected`.
 */
void check_write(const tw::table_writer& writer,
		 const std::size_t max_width,
		 std::string expected,
		 const std::string& what)
{
	/*
	 * Drop the leading newline so that each `expected` raw string
	 * literal may begin the box on its own line, vertically aligned
	 * with the rest of the box. Easier to read in this test file.
	 */
	if (!expected.empty() && expected.front() == '\n') {
		expected.erase(expected.begin());
	}

	std::ostringstream os;

	writer.write(os, max_width);

	const auto actual = os.str();
	const auto matches = actual == expected;

	ok(matches, "%s", what.c_str());

	if (!matches) {
		diag("Expected:\n%s", expected.c_str());
		diag("Actual:\n%s", actual.c_str());
	}
}

/*
 * Tests the basic layout of a two-column table with Unicode borders:
 * column widths driven by the widest cell, default left alignment for
 * strings, and default right alignment for integers.
 */
void test_basic_utf_8()
{
	diag("Basic Unicode-bordered table");

	tw::table_writer writer(cols(make_str_col_descr("Name"), make_int_col_descr("Age")), true);

	writer.append_row(row(tw::make_str_cell("Alice"), tw::make_signed_int_cell(30)));
	writer.append_row(row(tw::make_str_cell("Bob"), tw::make_signed_int_cell(7)));

	check_write(writer,
		    1000,
		    R"(
┏━━━━━━━┯━━━━━┓
┃ Name  │ Age ┃
┣━━━━━━━┿━━━━━┫
┃ Alice │  30 ┃
┃ Bob   │   7 ┃
┗━━━━━━━┷━━━━━┛
)",
		    "basic Unicode-bordered table");
}

/*
 * Tests that the ASCII fallback uses `+`, `-`, and `|` glyphs while
 * keeping the very same layout.
 */
void test_basic_ascii()
{
	diag("Basic ASCII-bordered table");

	tw::table_writer writer(cols(make_str_col_descr("Name"), make_int_col_descr("Age")), false);

	writer.append_row(row(tw::make_str_cell("Alice"), tw::make_signed_int_cell(30)));
	writer.append_row(row(tw::make_str_cell("Bob"), tw::make_signed_int_cell(7)));

	check_write(writer,
		    1000,
		    R"(
+-------+-----+
| Name  | Age |
+-------+-----+
| Alice |  30 |
| Bob   |   7 |
+-------+-----+
)",
		    "basic ASCII-bordered table");
}

/*
 * Tests a minimal table: a single column with a single row.
 */
void test_single_cell()
{
	diag("Single-column, single-row table");

	tw::table_writer writer(cols(make_str_col_descr("H")), true);

	writer.append_row(row(tw::make_str_cell("x")));

	check_write(writer,
		    1000,
		    R"(
┏━━━┓
┃ H ┃
┣━━━┫
┃ x ┃
┗━━━┛
)",
		    "single-cell table");
}

/*
 * Tests the three string cell alignments.
 *
 * Headers are always centered regardless of the cell alignment of
 * the column.
 */
void test_alignment()
{
	diag("Per-column cell alignment");

	tw::table_writer writer(cols(make_str_col_descr("Left", tw::table_cell_align::LEFT),
				     make_str_col_descr("Right", tw::table_cell_align::RIGHT),
				     make_str_col_descr("Center", tw::table_cell_align::CENTER)),
				true);

	writer.append_row(
		row(tw::make_str_cell("aa"), tw::make_str_cell("bb"), tw::make_str_cell("cc")));

	check_write(writer,
		    1000,
		    R"(
┏━━━━━━┯━━━━━━━┯━━━━━━━━┓
┃ Left │ Right │ Center ┃
┣━━━━━━┿━━━━━━━┿━━━━━━━━┫
┃ aa   │    bb │   cc   ┃
┗━━━━━━┷━━━━━━━┷━━━━━━━━┛
)",
		    "left, right, and center alignment");
}

/*
 * Tests that a centered cell with odd leftover padding biases the
 * smaller half to the left.
 */
void test_center_odd_padding()
{
	diag("Centering with odd padding");

	tw::table_writer writer(cols(make_str_col_descr("Header", tw::table_cell_align::CENTER)),
				true);

	writer.append_row(row(tw::make_str_cell("abc")));

	check_write(writer,
		    1000,
		    R"(
┏━━━━━━━━┓
┃ Header ┃
┣━━━━━━━━┫
┃  abc   ┃
┗━━━━━━━━┛
)",
		    "odd padding biases left");
}

/*
 * Tests that signed integer columns always group digits and handle
 * negatives and zero.
 */
void test_signed_int_grouping()
{
	diag("Signed integer digit grouping");

	tw::table_writer writer(cols(make_str_col_descr("K"), make_int_col_descr("V")), true);

	writer.append_row(row(tw::make_str_cell("big"), tw::make_signed_int_cell(1234567)));
	writer.append_row(row(tw::make_str_cell("kilo"), tw::make_signed_int_cell(1234)));
	writer.append_row(row(tw::make_str_cell("neg"), tw::make_signed_int_cell(-98765)));
	writer.append_row(row(tw::make_str_cell("zero"), tw::make_signed_int_cell(0)));

	check_write(writer,
		    1000,
		    R"(
┏━━━━━━┯━━━━━━━━━━━┓
┃  K   │     V     ┃
┣━━━━━━┿━━━━━━━━━━━┫
┃ big  │ 1,234,567 ┃
┃ kilo │     1,234 ┃
┃ neg  │   -98,765 ┃
┃ zero │         0 ┃
┗━━━━━━┷━━━━━━━━━━━┛
)",
		    "signed integer grouping with negatives, zero, and four digits");
}

/*
 * Tests that the column width grows to fit a header wider than any of
 * its cells.
 */
void test_header_wider_than_cells()
{
	diag("Header wider than cells");

	tw::table_writer writer(cols(make_str_col_descr("VeryLongHeader")), true);

	writer.append_row(row(tw::make_str_cell("x")));

	check_write(writer,
		    1000,
		    R"(
┏━━━━━━━━━━━━━━━━┓
┃ VeryLongHeader ┃
┣━━━━━━━━━━━━━━━━┫
┃ x              ┃
┗━━━━━━━━━━━━━━━━┛
)",
		    "header drives column width");
}

/*
 * Tests an arbitrary-precision integer column, including digit grouping
 * beyond the 64-bit range and a negative value.
 */
void test_bigint()
{
	diag("`bigint` column");

	{
		tw::table_writer writer(cols(make_str_col_descr("N"), make_bigint_col_descr("Big")),
					true);

		writer.append_row(row(tw::make_str_cell("huge"),
				      tw::make_bigint_cell(lttng::bigint(
					      std::string("123456789012345678901234567890")))));

		check_write(writer,
			    1000,
			    R"(
┏━━━━━━┯━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  N   │                   Big                   ┃
┣━━━━━━┿━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ huge │ 123,456,789,012,345,678,901,234,567,890 ┃
┗━━━━━━┷━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
)",
			    "huge `bigint` digit grouping");
	}

	{
		tw::table_writer writer(cols(make_bigint_col_descr("Big")), false);

		writer.append_row(
			row(tw::make_bigint_cell(lttng::bigint(std::string("-1234567890")))));

		check_write(writer,
			    1000,
			    R"(
+----------------+
|      Big       |
+----------------+
| -1,234,567,890 |
+----------------+
)",
			    "negative `bigint` digit grouping");
	}
}

/*
 * Tests that wide codepoints (East Asian as well as emoji) count as
 * two display columns when computing column widths and padding.
 */
void test_wide_code_points()
{
	diag("Wide codepoints");

	tw::table_writer writer(cols(make_str_col_descr("CJK"), make_int_col_descr("N")), true);

	writer.append_row(row(tw::make_str_cell("漢字"), tw::make_signed_int_cell(1)));
	writer.append_row(row(tw::make_str_cell("ab"), tw::make_signed_int_cell(2)));
	writer.append_row(row(tw::make_str_cell("😏😏"), tw::make_signed_int_cell(3)));

	check_write(writer,
		    1000,
		    R"(
┏━━━━━━┯━━━┓
┃ CJK  │ N ┃
┣━━━━━━┿━━━┫
┃ 漢字 │ 1 ┃
┃ ab   │ 2 ┃
┃ 😏😏 │ 3 ┃
┗━━━━━━┷━━━┛
)",
		    "wide codepoints (CJK and emoji) count as two columns");
}

/*
 * Tests that an empty string cell renders as blank padding.
 */
void test_empty_cell()
{
	diag("Empty string cell");

	tw::table_writer writer(cols(make_str_col_descr("A"), make_str_col_descr("B")), true);

	writer.append_row(row(tw::make_str_cell(""), tw::make_str_cell("y")));

	check_write(writer,
		    1000,
		    R"(
┏━━━┯━━━┓
┃ A │ B ┃
┣━━━┿━━━┫
┃   │ y ┃
┗━━━┷━━━┛
)",
		    "empty cell renders as blanks");
}

/*
 * Tests that a wrappable column too wide for `max_width` hard-wraps its
 * cell across multiple visual lines, while the non-wrappable column
 * appears only on the first line.
 */
void test_wrap_single_column()
{
	diag("Hard-wrapping a single wrappable column");

	tw::table_writer writer(cols(make_str_col_descr("Text", tw::table_cell_align::LEFT, true),
				     make_int_col_descr("N")),
				true);

	writer.append_row(row(tw::make_str_cell("abcdefghij"), tw::make_signed_int_cell(5)));

	check_write(writer,
		    16,
		    R"(
┏━━━━━━━━━━┯━━━┓
┃   Text   │ N ┃
┣━━━━━━━━━━┿━━━┫
┃ abcdefgh │ 5 ┃
┃ ij       │   ┃
┗━━━━━━━━━━┷━━━┛
)",
		    "wrappable cell hard-wraps, non-wrappable on first line only");
}

/*
 * Tests that two wrappable columns shrink in a round-robin fashion so
 * their widths end up differing by at most one.
 */
void test_wrap_two_columns()
{
	diag("Round-robin shrink of two wrappable columns");

	tw::table_writer writer(cols(make_str_col_descr("AAAA", tw::table_cell_align::LEFT, true),
				     make_str_col_descr("BBBB", tw::table_cell_align::LEFT, true)),
				true);

	writer.append_row(row(tw::make_str_cell("abcdefgh"), tw::make_str_cell("12345678")));

	check_write(writer,
		    20,
		    R"(
┏━━━━━━━━┯━━━━━━━━━┓
┃  AAAA  │  BBBB   ┃
┣━━━━━━━━┿━━━━━━━━━┫
┃ abcdef │ 1234567 ┃
┃ gh     │ 8       ┃
┗━━━━━━━━┷━━━━━━━━━┛
)",
		    "two wrappable columns shrink round-robin");
}

/*
 * Tests that a wrappable column never shrinks below its header width,
 * so the header keeps driving the floor of the wrap.
 */
void test_wrap_header_floor()
{
	diag("Wrappable column floors at header width");

	tw::table_writer writer(cols(make_str_col_descr("Header", tw::table_cell_align::LEFT, true),
				     make_int_col_descr("N")),
				true);

	writer.append_row(row(tw::make_str_cell("abcdefghijklmnop"), tw::make_signed_int_cell(1)));

	check_write(writer,
		    4,
		    R"(
┏━━━━━━━━┯━━━┓
┃ Header │ N ┃
┣━━━━━━━━┿━━━┫
┃ abcdef │ 1 ┃
┃ ghijkl │   ┃
┃ mnop   │   ┃
┗━━━━━━━━┷━━━┛
)",
		    "wrappable column floors at header width");
}

/*
 * Tests that a non-wrappable column never shrinks, even when the table
 * exceeds `max_width`.
 */
void test_no_shrink_non_wrappable()
{
	diag("Non-wrappable column never shrinks");

	tw::table_writer writer(cols(make_str_col_descr("Fixed")), true);

	writer.append_row(row(tw::make_str_cell("abcdefghij")));

	check_write(writer,
		    5,
		    R"(
┏━━━━━━━━━━━━┓
┃   Fixed    ┃
┣━━━━━━━━━━━━┫
┃ abcdefghij ┃
┗━━━━━━━━━━━━┛
)",
		    "non-wrappable column ignores max_width");
}

/*
 * Tests that when every wrappable column has saturated at its floor and
 * the table still exceeds `max_width`, the writer gives up and the box
 * stays wider than `max_width` instead of looping forever.
 */
void test_wrap_saturates()
{
	diag("Wrappable column saturates at its floor");

	tw::table_writer writer(cols(make_str_col_descr("H", tw::table_cell_align::LEFT, true)),
				true);

	writer.append_row(row(tw::make_str_cell("abcd")));

	check_write(writer,
		    3,
		    R"(
┏━━━━┓
┃ H  ┃
┣━━━━┫
┃ ab ┃
┃ cd ┃
┗━━━━┛
)",
		    "saturated wrappable column still exceeds max_width");
}

/*
 * Tests that hard-wrapping never splits a two-column-wide codepoint:
 * each visual line holds at most the column width in display columns,
 * and a wide codepoint that doesn't fit the remaining space moves to
 * the next line, leaving the leftover column blank.
 */
void test_wrap_wide_code_point()
{
	diag("Hard-wrapping with two-column-wide codepoints");

	{
		/*
		 * A column of width three can hold a single width-two
		 * codepoint per line, with one leftover padding column,
		 * since a second one wouldn't fit.
		 */
		tw::table_writer writer(
			cols(make_str_col_descr("W", tw::table_cell_align::LEFT, true)), true);

		writer.append_row(row(tw::make_str_cell("漢字漢字")));

		check_write(writer,
			    7,
			    R"(
┏━━━━━┓
┃  W  ┃
┣━━━━━┫
┃ 漢  ┃
┃ 字  ┃
┃ 漢  ┃
┃ 字  ┃
┗━━━━━┛
)",
			    "wide codepoint never splits across a line");
	}

	{
		/*
		 * A column of width four packs a wide and a narrow
		 * codepoint on the same line when they fit, and pushes
		 * a lone trailing wide codepoint to its own line.
		 */
		tw::table_writer writer(
			cols(make_str_col_descr("Text", tw::table_cell_align::LEFT, true),
			     make_int_col_descr("N")),
			true);

		writer.append_row(row(tw::make_str_cell("漢a字b漢"), tw::make_signed_int_cell(9)));

		check_write(writer,
			    11,
			    R"(
┏━━━━━━┯━━━┓
┃ Text │ N ┃
┣━━━━━━┿━━━┫
┃ 漢a  │ 9 ┃
┃ 字b  │   ┃
┃ 漢   │   ┃
┗━━━━━━┷━━━┛
)",
			    "wide and narrow codepoints pack within a line");
	}
}

/*
 * Tests that the alignment of a wrappable column applies to each
 * visual line of a wrapped cell, not just the first.
 */
void test_wrap_alignment()
{
	diag("Alignment of wrapped cells");

	tw::table_writer writer(
		cols(make_str_col_descr("Right", tw::table_cell_align::RIGHT, true),
		     make_str_col_descr("Center", tw::table_cell_align::CENTER, true)),
		true);

	writer.append_row(row(tw::make_str_cell("abcdefg"), tw::make_str_cell("0123456")));

	check_write(writer,
		    18,
		    R"(
┏━━━━━━━┯━━━━━━━━┓
┃ Right │ Center ┃
┣━━━━━━━┿━━━━━━━━┫
┃ abcde │ 012345 ┃
┃    fg │   6    ┃
┗━━━━━━━┷━━━━━━━━┛
)",
		    "right- and center-aligned wrapped chunks keep their alignment");
}

/*
 * Tests that several rows each wrap independently, every row spanning
 * exactly as many visual lines as its own widest wrapped cell needs.
 */
void test_wrap_multiple_rows()
{
	diag("Independent wrapping of multiple rows");

	tw::table_writer writer(cols(make_str_col_descr("Text", tw::table_cell_align::LEFT, true),
				     make_int_col_descr("N")),
				true);

	writer.append_row(row(tw::make_str_cell("aaaaa"), tw::make_signed_int_cell(1)));
	writer.append_row(row(tw::make_str_cell("bbbbbbb"), tw::make_signed_int_cell(2)));
	writer.append_row(row(tw::make_str_cell("cc"), tw::make_signed_int_cell(3)));

	check_write(writer,
		    10,
		    R"(
┏━━━━━━┯━━━┓
┃ Text │ N ┃
┣━━━━━━┿━━━┫
┃ aaaa │ 1 ┃
┃ a    │   ┃
┃ bbbb │ 2 ┃
┃ bbb  │   ┃
┃ cc   │ 3 ┃
┗━━━━━━┷━━━┛
)",
		    "each row wraps independently across visual lines");
}

} /* namespace */

int main()
{
	plan_tests(20);
	diag("`lttng::tw::table_writer` unit tests");

	test_basic_utf_8();
	test_basic_ascii();
	test_single_cell();
	test_alignment();
	test_center_odd_padding();
	test_signed_int_grouping();
	test_header_wider_than_cells();
	test_bigint();
	test_wide_code_points();
	test_empty_cell();
	test_wrap_single_column();
	test_wrap_two_columns();
	test_wrap_header_floor();
	test_no_shrink_non_wrappable();
	test_wrap_saturates();
	test_wrap_wide_code_point();
	test_wrap_alignment();
	test_wrap_multiple_rows();

	return exit_status();
}
