/*
 * SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_COMMON_TABLE_WRITER_HPP
#define LTTNG_COMMON_TABLE_WRITER_HPP

#include <common/bigint.hpp>
#include <common/tinyutf8.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <ostream>
#include <utility>
#include <vector>

namespace lttng {
namespace tw {

/*
 * Specifies how to align a table cell's data.
 */
enum class table_cell_align { LEFT, RIGHT, CENTER };

/*
 * Type-erased abstract base class for a single value that a column
 * descriptor renders.
 *
 * A `typed_table_cell` instance holds the concrete payload.
 */
class table_cell {
public:
	using uptr = std::unique_ptr<table_cell>;

	table_cell(const table_cell&) = delete;
	table_cell(table_cell&&) = delete;
	table_cell& operator=(const table_cell&) = delete;
	table_cell& operator=(table_cell&&) = delete;
	virtual ~table_cell() = default;

protected:
	table_cell() = default;
};

/*
 * Holds a single value of type `ValType` as a concrete table cell.
 *
 * Callers use it both to build rows (paired with a column descriptor
 * that expects the same `ValType`) and to downcast within concrete
 * table_col_descr::render() overrides.
 */
template <typename ValType>
class typed_table_cell final : public table_cell {
public:
	explicit typed_table_cell(ValType val) : _val(std::move(val))
	{
	}

	const ValType& val() const noexcept
	{
		return _val;
	}

private:
	ValType _val;
};

/*
 * Helper to build a table cell wrapping a
 * `tiny_utf8::utf8_string` value.
 *
 * `str` must not contain any SGR code.
 */
table_cell::uptr make_str_cell(tiny_utf8::utf8_string str);

/*
 * Helper to build a table cell wrapping an `std::int64_t` value.
 */
table_cell::uptr make_signed_int_cell(std::int64_t val);

/*
 * Helper to build a table cell wrapping a `bigint` value.
 */
table_cell::uptr make_bigint_cell(bigint val);

/*
 * Describes a table column: its header, alignment, whether it can
 * hard-wrap, and how to render a `table_cell` instance for that column
 * into a display string.
 *
 * A concrete derived class downcasts the incoming `table_cell` instance
 * to the `typed_table_cell<...>` type it expects. The caller must
 * construct table cells with a matching value type.
 */
class table_col_descr {
public:
	using uptr = std::unique_ptr<table_col_descr>;

	table_col_descr(const table_col_descr&) = delete;
	table_col_descr(table_col_descr&&) = delete;
	table_col_descr& operator=(const table_col_descr&) = delete;
	table_col_descr& operator=(table_col_descr&&) = delete;
	virtual ~table_col_descr() = default;

	const tiny_utf8::utf8_string& header() const noexcept
	{
		return _header;
	}

	table_cell_align cell_align() const noexcept
	{
		return _cell_align;
	}

	bool is_wrappable() const noexcept
	{
		return _is_wrappable;
	}

	virtual tiny_utf8::utf8_string render(const table_cell& cell) const = 0;

protected:
	table_col_descr(tiny_utf8::utf8_string header,
			table_cell_align cell_align,
			bool is_wrappable) :
		_header(std::move(header)), _cell_align(cell_align), _is_wrappable(is_wrappable)
	{
	}

private:
	tiny_utf8::utf8_string _header;
	table_cell_align _cell_align;
	bool _is_wrappable;
};

/*
 * Helper which describes a table column of `std::int64_t` values.
 *
 * `render()` expects `typed_table_cell<std::int64_t>` cells, and always
 * applies digit grouping to the decimal representation of the value.
 */
class table_signed_int_col_descr final : public table_col_descr {
public:
	/*
	 * Builds a table column of `std::int64_t` values.
	 *
	 * `header` must not contain any SGR code.
	 */
	explicit table_signed_int_col_descr(tiny_utf8::utf8_string header,
					    table_cell_align cell_align = table_cell_align::RIGHT,
					    bool is_wrappable = false) :
		table_col_descr(std::move(header), cell_align, is_wrappable)
	{
	}

	tiny_utf8::utf8_string render(const table_cell& cell) const override;
};

/*
 * Helper which describes a table column of `bigint` values.
 *
 * `render()` expects `typed_table_cell<bigint>` cells, and always
 * applies digit grouping to the decimal representation of the value.
 */
class table_bigint_col_descr final : public table_col_descr {
public:
	/*
	 * Builds a table column of `bigint` values.
	 *
	 * `header` must not contain any SGR code.
	 */
	explicit table_bigint_col_descr(tiny_utf8::utf8_string header,
					table_cell_align cell_align = table_cell_align::RIGHT,
					bool is_wrappable = false) :
		table_col_descr(std::move(header), cell_align, is_wrappable)
	{
	}

	tiny_utf8::utf8_string render(const table_cell& cell) const override;
};

/*
 * Helper which describes a table column of
 * `tiny_utf8::utf8_string` values.
 *
 * `render()` expects `typed_table_cell<tiny_utf8::utf8_string>` cells.
 */
class table_str_col_descr final : public table_col_descr {
public:
	/*
	 * Builds a table column of `tiny_utf8::utf8_string` values.
	 *
	 * `header` must not contain any SGR code.
	 */
	explicit table_str_col_descr(tiny_utf8::utf8_string header,
				     table_cell_align cell_align = table_cell_align::LEFT,
				     bool is_wrappable = false) :
		table_col_descr(std::move(header), cell_align, is_wrappable)
	{
	}

	tiny_utf8::utf8_string render(const table_cell& cell) const override;
};

namespace details {

struct box_glyphs;

} /* namespace details */

/*
 * Writes a plain-text table.
 *
 * The user provides the schema (columns) at construction and appends
 * rows with append_row().
 *
 * Each cell must hold a value of which the type matches what the
 * render() method of its column descriptor expects.
 *
 * write() writes the plain text table to some output stream.
 */
class table_writer final {
public:
	/*
	 * Builds a plain text table writer with the column
	 * schema `col_descrs`.
	 *
	 * If `use_utf_8_borders` is true, then write() draws the box
	 * with Unicode box-drawing characters; otherwise, it falls back
	 * to pure ASCII.
	 *
	 * If `use_term_codes` is true, then write() emits terminal
	 * codes to style the output (for example, bold headers);
	 * otherwise, the output is plain text. The actual emission of
	 * those codes is also subject to the rules of lttng::mint().
	 *
	 * `col_descrs` must not be empty.
	 */
	table_writer(std::vector<table_col_descr::uptr> col_descrs,
		     bool use_utf_8_borders,
		     bool use_term_codes = false);

	table_writer(const table_writer&) = delete;
	table_writer(table_writer&&) = delete;
	table_writer& operator=(const table_writer&) = delete;
	table_writer& operator=(table_writer&&) = delete;
	~table_writer() = default;

	/*
	 * Appends a row of `cells` to the table.
	 *
	 * The size of `cells` must be equal to the column count of
	 * this writer.
	 */
	void append_row(std::vector<table_cell::uptr> cells);

	/*
	 * Renders every cell to a string through its corresponding
	 * column descriptor, and then computes per-column widths from
	 * the widest visible cell (UTF-8 codepoint count) and writes a
	 * bordered box.
	 *
	 * If the total width exceeds `max_width`, then this function
	 * shrinks the wrappable columns one cell at a time,
	 * round-robin, until the table fits. A column won't shrink
	 * below the larger of its header length and one. The widths of
	 * the wrappable columns end up differing by at most one (modulo
	 * a column that saturated early). If every wrappable column
	 * saturates before the table fits, then the box unfortunately
	 * still exceeds `max_width`.
	 *
	 * Each shrunk cell then hard-wraps across multiple visual lines
	 * within the same row. Non-wrappable cells of a wrapped row
	 * appear only on the first visual line.
	 *
	 * This table writer must have at least one row.
	 */
	void write(std::ostream& os, std::size_t max_width) const;

private:
	/*
	 * Per-column display widths, in UTF-8 codepoints, indexed
	 * by column.
	 */
	using _cell_widths = std::vector<std::size_t>;

	/*
	 * One row of cells already rendered to display strings by their
	 * respective column descriptors, indexed by column.
	 */
	using _rendered_row = std::vector<tiny_utf8::utf8_string>;

	/*
	 * Returns the column headers as a synthetic row, so that the
	 * same row rendering code can lay them out within the box.
	 */
	_rendered_row _headers_as_cells() const;

	/*
	 * Writes a single row of `cells` (already pre-rendered to
	 * strings) to `os`, using the per-column display widths in
	 * `widths` and the alignment of each column descriptor.
	 *
	 * This function hard-wraps every wrappable cell wider than its
	 * column width across multiple visual lines. The row spans as
	 * many lines as the wrappable cell that produces the most
	 * chunks; other wrappable cells leave their trailing lines
	 * blank, and non-wrappable cells appear only on the first
	 * visual line.
	 */
	void _render_row(std::ostream& os,
			 const _cell_widths& widths,
			 const _rendered_row& cells,
			 bool is_header) const;

	std::vector<table_col_descr::uptr> _col_descrs;
	std::vector<std::vector<table_cell::uptr>> _rows;
	const details::box_glyphs *_box_glyphs;
	bool _use_term_codes;
};

} /* namespace tw */
} /* namespace lttng */

#endif /* LTTNG_COMMON_TABLE_WRITER_HPP */
