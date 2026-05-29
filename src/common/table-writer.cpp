/*
 * SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "table-writer.hpp"

#include <common/error.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/macros.hpp>
#include <common/make-unique.hpp>
#include <common/mint.hpp>
#include <common/tinyutf8.hpp>
#include <common/utils.hpp>

#include <algorithm>

namespace lttng {
namespace tw {

table_cell::uptr make_str_cell(tiny_utf8::utf8_string str)
{
	return lttng::make_unique<typed_table_cell<tiny_utf8::utf8_string>>(std::move(str));
}

table_cell::uptr make_signed_int_cell(const std::int64_t val)
{
	return lttng::make_unique<typed_table_cell<std::int64_t>>(val);
}

table_cell::uptr make_bigint_cell(bigint val)
{
	return lttng::make_unique<typed_table_cell<bigint>>(std::move(val));
}

tiny_utf8::utf8_string table_signed_int_col_descr::render(const table_cell& cell) const
{
	const auto& typed_cell = static_cast<const typed_table_cell<std::int64_t>&>(cell);

	return fmt::format("{}", fmt::group_digits(typed_cell.val()));
}

tiny_utf8::utf8_string table_bigint_col_descr::render(const table_cell& cell) const
{
	const auto& typed_cell = static_cast<const typed_table_cell<bigint>&>(cell);

	return typed_cell.val().grouped_str();
}

tiny_utf8::utf8_string table_str_col_descr::render(const table_cell& cell) const
{
	const auto& typed_cell = static_cast<const typed_table_cell<tiny_utf8::utf8_string>&>(cell);

	return typed_cell.val();
}

namespace details {

/*
 * Set of glyphs used to draw a box.
 */
struct box_glyphs final {
	const char *top_left;
	const char *top_join;
	const char *top_right;
	const char *mid_left;
	const char *mid_join;
	const char *mid_right;
	const char *bot_left;
	const char *bot_join;
	const char *bot_right;
	const char *horiz;
	const char *vert_outer;
	const char *vert_inner;
};

} /* namespace details */

namespace {

const details::box_glyphs& select_box_glyphs(const bool use_utf_8_borders) noexcept
{
	static const details::box_glyphs unicode_glyphs = {
		"┏", "┯", "┓", "┣", "┿", "┫", "┗", "┷", "┛", "━", "┃", "│",
	};

	static const details::box_glyphs ascii_glyphs = {
		"+", "+", "+", "+", "+", "+", "+", "+", "+", "-", "|", "|",
	};

	return use_utf_8_borders ? unicode_glyphs : ascii_glyphs;
}

} /* namespace */

table_writer::table_writer(std::vector<table_col_descr::uptr> col_descrs,
			   const bool use_utf_8_borders,
			   const bool use_term_codes) :
	_col_descrs(std::move(col_descrs)),
	_box_glyphs(&select_box_glyphs(use_utf_8_borders)),
	_use_term_codes(use_term_codes)
{
	LTTNG_ASSERT(!_col_descrs.empty());
}

void table_writer::append_row(std::vector<table_cell::uptr> cells)
{
	LTTNG_ASSERT(cells.size() == _col_descrs.size());
	_rows.push_back(std::move(cells));
}

table_writer::_rendered_row table_writer::_headers_as_cells() const
{
	_rendered_row headers;

	headers.reserve(_col_descrs.size());

	for (const auto& col : _col_descrs) {
		headers.push_back(col->header());
	}

	return headers;
}

namespace {

/*
 * Splits `str` into chunks of at most `max_width` display columns each.
 *
 * The width of each chunk is the sum of utils_codepoint_width() for its
 * codepoints, so wide codepoints count as two columns.
 *
 * `max_width` must be at least two: a single codepoint may be two
 * display columns wide, and since this function never breaks within a
 * codepoint, a smaller `max_width` couldn't guarantee that each chunk
 * fits. This also ensures that every chunk holds at least one
 * codepoint, so that the loop always makes progress.
 *
 * The split is a hard wrap: it doesn't try to break on spaces or any
 * other boundary.
 */
std::vector<tiny_utf8::utf8_string> hard_wrap_utf_8(const tiny_utf8::utf8_string& str,
						    const std::size_t max_width)
{
	LTTNG_ASSERT(max_width >= 2);

	std::vector<tiny_utf8::utf8_string> chunks;

	for (auto chunk_begin = str.raw_cbegin(); chunk_begin != str.raw_cend();) {
		/* Find end of current chunk */
		auto chunk_end = chunk_begin;

		{
			std::size_t chunk_width = 0;

			while (chunk_end != str.raw_cend()) {
				const auto cp_width = utils_codepoint_width(*chunk_end);

				if (chunk_width + cp_width > max_width) {
					break;
				}

				chunk_width += cp_width;
				++chunk_end;
			}
		}

		/* Append this chunk */
		chunks.emplace_back(chunk_begin, chunk_end);

		/* New chunk starts at the end of current chunk */
		chunk_begin = chunk_end;
	}

	return chunks;
}

/*
 * Writes `count` spaces to `os`.
 */
void write_spaces(std::ostream& os, const std::size_t count)
{
	for (std::size_t i = 0; i < count; ++i) {
		os << ' ';
	}
}

/*
 * Writes a single horizontal box separator row to `os`.
 *
 * `left`, `join`, and `right` are the corner/joint glyphs for the left
 * edge, between-column joins, and right edge respectively.
 *
 * `horiz` fills each column span, which is `widths[col_idx] + 2` to
 * cover the cell content plus the one-space padding on each side.
 */
void render_sep(std::ostream& os,
		const std::vector<std::size_t>& widths,
		const char *const left,
		const char *const join,
		const char *const right,
		const char *const horiz)
{
	os << left;

	for (std::size_t col_i = 0; col_i < widths.size(); ++col_i) {
		const auto col_span = widths[col_i] + 2;

		for (std::size_t fill_pos = 0; fill_pos < col_span; ++fill_pos) {
			os << horiz;
		}

		os << (col_i + 1 == widths.size() ? right : join);
	}

	os << '\n';
}

} /* namespace */

void table_writer::_render_row(std::ostream& os,
			       const _cell_widths& widths,
			       const _rendered_row& cells,
			       const bool is_header) const
{
	/*
	 * Pre-wrap every wrappable column.
	 *
	 * The widest chunk sequence drives how many visual lines this
	 * row spans; shorter ones pad with empty strings on the
	 * trailing lines.
	 */
	std::vector<std::vector<tiny_utf8::utf8_string>> wrap_chunks(widths.size());
	std::size_t line_count = 1;

	for (std::size_t i = 0; i < _col_descrs.size(); ++i) {
		if (_col_descrs[i]->is_wrappable()) {
			wrap_chunks[i] = hard_wrap_utf_8(cells[i], widths[i]);
			line_count = std::max(line_count, wrap_chunks[i].size());
		}
	}

	for (std::size_t line_idx = 0; line_idx < line_count; ++line_idx) {
		os << _box_glyphs->vert_outer;

		for (std::size_t i = 0; i < widths.size(); ++i) {
			os << ' ';

			tiny_utf8::utf8_string text;

			if (_col_descrs[i]->is_wrappable()) {
				/* One wrap chunk per visual line */
				text = line_idx < wrap_chunks[i].size() ? wrap_chunks[i][line_idx] :
									  tiny_utf8::utf8_string();
			} else {
				/*
				 * Non-wrappable cells only appear on
				 * the first visual line.
				 */
				text = line_idx == 0 ? cells[i] : tiny_utf8::utf8_string();
			}

			const auto text_width = utils_utf_8_string_width(text);
			const auto padding = widths[i] >= text_width ? widths[i] - text_width : 0;

			/*
			 * Compute padding from the plain text display
			 * width, but write the bold form so that ANSI
			 * escape codes don't count towards the
			 * column width.
			 */
			const auto text_to_write = (is_header && _use_term_codes && !text.empty()) ?
				tiny_utf8::utf8_string(mint_format("[!*]{}[/]", text.cpp_str())) :
				std::move(text);

			/*
			 * Header cells are always centered within their
			 * column, regardless of the column's own
			 * cell alignment.
			 */
			const auto align = is_header ? table_cell_align::CENTER :
						       _col_descrs[i]->cell_align();

			switch (align) {
			case table_cell_align::LEFT:
				os << text_to_write;
				write_spaces(os, padding);
				break;
			case table_cell_align::RIGHT:
				write_spaces(os, padding);
				os << text_to_write;
				break;
			case table_cell_align::CENTER:
			{
				const auto left_pad = padding / 2;

				write_spaces(os, left_pad);
				os << text_to_write;
				write_spaces(os, padding - left_pad);
				break;
			}
			}

			os << ' '
			   << (i + 1 == widths.size() ? _box_glyphs->vert_outer :
							_box_glyphs->vert_inner);
		}

		os << '\n';
	}
}

void table_writer::write(std::ostream& os, const std::size_t max_width) const
{
	LTTNG_ASSERT(!_rows.empty());

	const auto col_count = _col_descrs.size();

	/*
	 * Pre-render each cell to a display string through its
	 * column descriptor.
	 */
	std::vector<_rendered_row> rendered_rows;

	rendered_rows.reserve(_rows.size());

	for (const auto& row : _rows) {
		_rendered_row rendered_row;

		rendered_row.reserve(col_count);

		for (std::size_t i = 0; i < col_count; ++i) {
			rendered_row.push_back(_col_descrs[i]->render(*row[i]));
		}

		rendered_rows.push_back(std::move(rendered_row));
	}

	_cell_widths widths(col_count, 0);

	for (std::size_t i = 0; i < col_count; ++i) {
		widths[i] = utils_utf_8_string_width(_col_descrs[i]->header());
	}

	for (const auto& rendered_row : rendered_rows) {
		for (std::size_t i = 0; i < col_count; ++i) {
			widths[i] = std::max(widths[i], utils_utf_8_string_width(rendered_row[i]));
		}
	}

	/*
	 * hard_wrap_utf_8() requires the maximum width to be ≥ 2,
	 * therefore no wrappable column may be narrower than two
	 * display columns.
	 *
	 * A column can otherwise be one (or zero) wide when its header
	 * and every cell are that narrow; the shrink loop below never
	 * widens a column, so enforce the minimum here.
	 */
	for (std::size_t i = 0; i < col_count; ++i) {
		if (_col_descrs[i]->is_wrappable()) {
			widths[i] = std::max<std::size_t>(2, widths[i]);
		}
	}

	/*
	 * Total width is the sum of column widths + 2 padding chars per
	 * column + (`col_count` + 1) vertical separators.
	 */
	const auto total_width = [&] {
		std::size_t total = col_count + 1;

		for (const auto col_width : widths) {
			total += col_width + 2;
		}

		return total;
	};

	/*
	 * Shrink the wrappable columns one cell at a time, round robin,
	 * until the table fits or every wrappable column hits its floor
	 * (the larger of its header width and two).
	 *
	 * The floor is two, not one, because hard_wrap_utf_8() never
	 * breaks within a codepoint: a single codepoint may be two
	 * display columns wide, so a floor of one would let such a
	 * codepoint overflow its column and misalign the box.
	 *
	 * This naturally distributes the overflow across the wrappable
	 * columns: their widths end up differing by at most one (modulo
	 * a column that saturates early).
	 *
	 * Shrunk cells then hard-wrap across multiple visual lines at
	 * render time. If every wrappable column saturates before the
	 * table fits, the box unfortunately still exceeds `max_width`.
	 */
	while (total_width() > max_width) {
		auto any_shrunk = false;

		for (std::size_t i = 0; i < col_count; ++i) {
			if (!_col_descrs[i]->is_wrappable()) {
				continue;
			}

			if (widths[i] >
			    std::max<std::size_t>(
				    2, utils_utf_8_string_width(_col_descrs[i]->header()))) {
				/* Shrink this one */
				--widths[i];
				any_shrunk = true;

				if (total_width() <= max_width) {
					/* Reached! */
					break;
				}
			}
		}

		if (!any_shrunk) {
			/*
			 * Every wrappable column is already at its
			 * floor: no further pass can reduce the total:
			 * give up to avoid looping forever.
			 */
			break;
		}
	}

	/* Top edge of the box */
	render_sep(os,
		   widths,
		   _box_glyphs->top_left,
		   _box_glyphs->top_join,
		   _box_glyphs->top_right,
		   _box_glyphs->horiz);

	/* Header row */
	_render_row(os, widths, _headers_as_cells(), true);

	/* Separator between header and data */
	render_sep(os,
		   widths,
		   _box_glyphs->mid_left,
		   _box_glyphs->mid_join,
		   _box_glyphs->mid_right,
		   _box_glyphs->horiz);

	/* Data rows */
	for (const auto& row : rendered_rows) {
		_render_row(os, widths, row, false);
	}

	/* Bottom edge of the box */
	render_sep(os,
		   widths,
		   _box_glyphs->bot_left,
		   _box_glyphs->bot_join,
		   _box_glyphs->bot_right,
		   _box_glyphs->horiz);
}

} /* namespace tw */
} /* namespace lttng */
