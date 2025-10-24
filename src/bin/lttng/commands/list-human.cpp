/*
 * SPDX-FileCopyrightText: 2025 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "list-common.hpp"
#include "list-human.hpp"
#include "list-wrappers.hpp"
#include "lttng/channel.h"
#include "lttng/domain.h"
#include "lttng/stream-info.h"

#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/macros.hpp>
#include <common/make-unique.hpp>
#include <common/mi-lttng.hpp>
#include <common/mint.hpp>
#include <common/time.hpp>
#include <common/utils.hpp>

#include <vendor/optional.hpp>

#include <cctype>
#include <cstdint>
#include <limits>
#include <mutex>
#include <sys/ioctl.h>
#include <unistd.h>
#include <vector>

namespace {

/*
 * Returns the terminal width using ioctl(), caching the result.
 *
 * If this function cannot determine the current terminal width, it
 * returns "infinity" (indicating no wrapping).
 */
std::size_t term_columns() noexcept
{
	static std::once_flag init_flag;
	static std::size_t width = std::numeric_limits<std::size_t>::max();

	std::call_once(init_flag, [] {
		struct winsize ws;

		if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
			width = ws.ws_col;
		}
	});

	return width;
}

class node;

/* Ordered list of nodes */
using node_list = std::vector<std::unique_ptr<node>>;

/*
 * Abstract node base class.
 *
 * Offers children() to access children.
 */
class node {
protected:
	explicit node(node_list children = {}) : _children(std::move(children))
	{
	}

public:
	virtual ~node() = default;
	node(const node&) = delete;
	node(node&&) = delete;
	node& operator=(const node&) = delete;
	node& operator=(node&&) = delete;

	const node_list& children() const noexcept
	{
		return _children;
	}

private:
	std::vector<std::unique_ptr<node>> _children;
};

/*
 * Abstract base class for the value of a single property.
 *
 * A derived class must implement the _render() method to create a
 * corresponding formatted value string.
 */
class property_value {
protected:
	explicit property_value() = default;

public:
	virtual ~property_value() = default;
	property_value(const property_value&) = delete;
	property_value(property_value&&) = delete;
	property_value& operator=(const property_value&) = delete;
	property_value& operator=(property_value&&) = delete;

	/*
	 * Returns the formatted string for this value.
	 */
	std::string render() const
	{
		return this->_render();
	}

private:
	virtual std::string _render() const = 0;
};

/*
 * Raw value: _render() returns the contained string as is.
 */
class raw_property_value final : public property_value {
public:
	explicit raw_property_value(std::string value) : _value(std::move(value))
	{
	}

private:
	std::string _render() const override
	{
		return _value;
	}

	std::string _value;
};

/*
 * General string value.
 */
class string_property_value : public property_value {
public:
	explicit string_property_value(std::string value) : _value(std::move(value))
	{
	}

private:
	std::string _render() const override
	{
		return lttng::mint_format("[!]{}[/]", _value);
	}

protected:
	std::string _value;
};

/*
 * Literal string: _render() puts backticks around.
 */
class literal_string_property_value final : public string_property_value {
public:
	explicit literal_string_property_value(std::string value) :
		string_property_value(std::move(value))
	{
	}

private:
	std::string _render() const override
	{
		return lttng::mint_format("`[!]{}[/]`", _value);
	}
};

/*
 * Data size value.
 */
class size_property_value final : public property_value {
public:
	explicit size_property_value(const std::uint64_t bytes) : _bytes(bytes)
	{
	}

private:
	std::string _render() const override
	{
		const auto val_unit_pair = utils_value_unit_from_size(_bytes);

		return lttng::mint_format(
			"[!]{:.2f}[/] {}", val_unit_pair.first, val_unit_pair.second);
	}

	std::uint64_t _bytes;
};

std::string format_period(const std::uint64_t period_us)
{
	if (period_us < 1000) {
		return lttng::mint_format("[!]{}[/] {}", period_us, USEC_UNIT);
	}

	const auto value_unit = utils_value_unit_from_period(period_us);

	return lttng::mint_format("[!]{:.2f}[/] {}", value_unit.first, value_unit.second);
}

/*
 * Period (interval) value.
 */
class period_property_value final : public property_value {
public:
	explicit period_property_value(const std::uint64_t period_us) : _period_us(period_us)
	{
	}

private:
	std::string _render() const override
	{
		if (_period_us == 0) {
			return lttng::mint("[!]Inactive[/]");
		}

		return format_period(_period_us);
	}

	std::int64_t _period_us;
};

/*
 * Integral count value.
 */
class count_property_value final : public property_value {
public:
	explicit count_property_value(const std::int64_t count) : _count(count)
	{
	}

private:
	std::string _render() const override
	{
		return lttng::mint_format("[!]{}[/]", utils_format_integer_grouped(_count));
	}

	std::int64_t _count;
};

/*
 * Property: a key (no SGR codes) and a value.
 */
struct property final {
	std::string key;
	std::unique_ptr<property_value> value;

	bool operator<(const property& other) const noexcept
	{
		return key < other.key;
	}
};

/* Ordered set of properties */
using property_set = std::set<property>;

property make_raw_property(std::string key, std::string value)
{
	return { std::move(key), lttng::make_unique<raw_property_value>(std::move(value)) };
}

property make_string_property(std::string key, std::string value)
{
	return { std::move(key), lttng::make_unique<string_property_value>(std::move(value)) };
}

property make_literal_string_property(std::string key, std::string value)
{
	return { std::move(key),
		 lttng::make_unique<literal_string_property_value>(std::move(value)) };
}

property make_size_property(std::string key, const std::uint64_t bytes)
{
	return { std::move(key), lttng::make_unique<size_property_value>(bytes) };
}

property make_period_property(std::string key, const std::uint64_t period_us)
{
	return { std::move(key), lttng::make_unique<period_property_value>(period_us) };
}

property make_count_property(std::string key, const std::int64_t count)
{
	return { std::move(key), lttng::make_unique<count_property_value>(count) };
}

/*
 * Property set node.
 *
 * An instance holds a set of properties.
 *
 * It's a single (leaf) node because then it's easier to vertically
 * align values when rendering (if need be). See max_key_length().
 */
class property_set_node final : public node {
public:
	explicit property_set_node(property_set properties) : _properties(std::move(properties))
	{
		LTTNG_ASSERT(!_properties.empty());

		/* Compute maximum key length */
		for (const auto& prop : _properties) {
			_max_key_len =
				std::max(_max_key_len, lttng::mint_escape_ansi(prop.key).length());
		}
	}

	const property_set& properties() const noexcept
	{
		return _properties;
	}

	std::size_t max_key_length() const noexcept
	{
		return _max_key_len;
	}

private:
	property_set _properties;
	std::size_t _max_key_len = 0;
};

/*
 * Block node.
 *
 * A block node (leaf) has a title (expected to contain SGR codes) and
 * some content lines with custom formatting.
 */
class block_node final : public node {
public:
	explicit block_node(std::string title, std::vector<std::string> lines) :
		_title(std::move(title)), _lines(std::move(lines))
	{
		LTTNG_ASSERT(!_title.empty());
		LTTNG_ASSERT(!_lines.empty());
	}

	const std::string& title() const noexcept
	{
		return _title;
	}

	const std::vector<std::string>& lines() const noexcept
	{
		return _lines;
	}

private:
	std::string _title;
	std::vector<std::string> _lines;
};

/*
 * Group node.
 *
 * A group node has a title (expected to contain SGR codes), optional
 * tags, a type, and children.
 */
class group_node final : public node {
public:
	enum class type {
		/* Default */
		DEFAULT,

		/* A main object */
		MAIN,

		/* Enabled state */
		ENABLED,

		/* Disabled state */
		DISABLED,

		/* Active state */
		ACTIVE,

		/* Inactive state */
		INACTIVE,
	};

	explicit group_node(std::string title,
			    node_list children = {},
			    const type node_type = type::DEFAULT,
			    std::vector<std::string> tags = {}) :
		node(std::move(children)),
		_title(std::move(title)),
		_type(node_type),
		_tags(std::move(tags))
	{
		LTTNG_ASSERT(!_title.empty());
	}

	const std::string& title() const noexcept
	{
		return _title;
	}

	type type() const noexcept
	{
		return _type;
	}

	const std::vector<std::string>& tags() const noexcept
	{
		return _tags;
	}

private:
	std::string _title;
	enum type _type;
	std::vector<std::string> _tags;
};

std::unique_ptr<node> make_property_set_node(property_set properties)
{
	return lttng::make_unique<property_set_node>(std::move(properties));
}

std::unique_ptr<node> make_block_node(std::string title, std::vector<std::string> lines)
{
	return lttng::make_unique<block_node>(std::move(title), std::move(lines));
}

std::unique_ptr<node> make_group_node(std::string title,
				      node_list children = {},
				      const enum group_node::type type = group_node::type::DEFAULT,
				      std::vector<std::string> tags = {})
{
	return lttng::make_unique<group_node>(
		std::move(title), std::move(children), type, std::move(tags));
}

std::unique_ptr<node> make_group_node_underlined_title(std::string title, node_list children = {})
{
	return lttng::make_unique<group_node>(lttng::mint_format("[_]{}[/]:", title),
					      std::move(children));
}

std::unique_ptr<node> make_block_node_underlined_title(std::string title,
						       std::vector<std::string> lines)
{
	return lttng::make_unique<block_node>(lttng::mint_format("[_]{}[/]:", title),
					      std::move(lines));
}

const char *tag_open_char() noexcept
{
	return locale_supports_utf8() ? "❬" : "<";
}

const char *tag_close_char() noexcept
{
	return locale_supports_utf8() ? "❭" : ">";
}

/*
 * Node renderer.
 *
 * Offers the render() method to render a node to some output stream.
 *
 * The renderer automatically truncates lines which would be larger than
 * the current width of the terminal (if available).
 */
class renderer final {
public:
	explicit renderer(const bool is_compact, const bool no_truncate) :
		_is_compact(is_compact), _no_truncate(no_truncate)
	{
	}

	/*
	 * Renders `root` to the output stream `os`.
	 */
	void render(const node& root, std::ostream& os)
	{
		_cur_os = &os;
		_pending_empty_line = false;
		_render_node(root, 0, true);
	}

private:
	static const char *_bullet_char() noexcept
	{
		return locale_supports_utf8() ? "🞂" : ">";
	}

	/*
	 * Returns the number of UTF-8 codepoints in `str`.
	 */
	static std::size_t _utf8_string_length(const std::string& str) noexcept
	{
		std::size_t count = 0;

		for (std::size_t i = 0; i < str.length(); ++i) {
			if ((static_cast<unsigned char>(str[i]) & 0xc0) != 0x80) {
				++count;
			}
		}

		return count;
	}

	/*
	 * Returns the truncated version of the line `line` (without
	 * any newline) if it exceeds the terminal width, adding `…`
	 * at the end.
	 *
	 * Accounts for SGR escape codes and UTF-8 code unit sequences.
	 */
	static std::string _truncate_line(const std::string& line)
	{
		if (_utf8_string_length(lttng::mint_escape_ansi(line)) <= term_columns()) {
			/* Already fits: return as is */
			return line;
		}

		/*
		 * Truncation needed: find the byte position which
		 * corresponds to `term_columns() - 1` visible
		 * characters.
		 */
		std::size_t visible_count = 0;
		std::size_t byte_pos = 0;

		while (byte_pos < line.length() && visible_count < term_columns() - 1) {
			/* Check if we're at the start of an SGR escape sequence */
			if (line[byte_pos] == '\033' && line[byte_pos + 1] == '[') {
				/* Skip until terminating `m` */
				while (line[byte_pos] != 'm') {
					++byte_pos;
				}

				/* Skip `m` */
				++byte_pos;
			} else {
				/* Regular character: counts toward visible width */
				++byte_pos;

				if (locale_supports_utf8()) {
					/* Skip any UTF-8 continuation byte */
					while (byte_pos < line.length() &&
					       (static_cast<unsigned char>(line[byte_pos]) &
						0xc0) == 0x80) {
						++byte_pos;
					}
				}

				++visible_count;
			}
		}

		/* Truncate and add ellipsis */
		return line.substr(0, byte_pos) +
			lttng::mint_format("[w:r*]{}[/]", locale_supports_utf8() ? "…" : "/");
	}

	/*
	 * Returns the node prefix for the depth `depth` with the
	 * bullet `bullet`.
	 */
	static std::string _prefix_with_bullet(const unsigned int depth, const std::string& bullet)
	{
		std::string prefix;

		if (depth > 0) {
			prefix = std::string(depth * 2, ' ');
		}

		prefix += lttng::format("{} ", bullet);
		return prefix;
	}

	/*
	 * Writes the truncated version of `line` and a newline to the
	 * current output stream.
	 */
	void _write_line(const std::string& line)
	{
		if (_pending_empty_line) {
			*_cur_os << '\n';
			_pending_empty_line = false;
		}

		if (_no_truncate) {
			*_cur_os << line << '\n';
		} else {
			*_cur_os << _truncate_line(line) << '\n';
		}
	}

	/*
	 * Renders the node `n`.
	 */
	void _render_node(const node& n, const unsigned int depth, const bool is_first_sibling)
	{
		const auto is_multi_line = dynamic_cast<const block_node *>(&n) ||
			!n.children().empty();

		if (!_is_compact && !is_first_sibling && is_multi_line) {
			_pending_empty_line = true;
		}

		/* No I don't feel bad */
		if (const auto property_set_n = dynamic_cast<const property_set_node *>(&n)) {
			_render_property_set(*property_set_n, depth);
		} else if (const auto block_n = dynamic_cast<const block_node *>(&n)) {
			_render_block(*block_n, depth);
		} else if (const auto group_n = dynamic_cast<const group_node *>(&n)) {
			_render_group(*group_n, depth);
		} else {
			std::abort();
		}

		if (!_is_compact && is_multi_line) {
			_pending_empty_line = true;
		}
	}

	/*
	 * Renders the property set node `prop_set_n`.
	 */
	void _render_property_set(const property_set_node& prop_set_n, const unsigned int depth)
	{
		/* Render property lines */
		for (const auto& prop : prop_set_n.properties()) {
			_write_line(lttng::format(
				"{}{:<{}} {}",
				_prefix_with_bullet(depth,
						    lttng::mint_format("[-]{}[/]", _bullet_char())),
				prop.key + ':',
				prop_set_n.max_key_length() + 1,
				prop.value->render()));
		}
	}

	/*
	 * Renders the block node `block_n`.
	 */
	void _render_block(const block_node& block_n, const unsigned int depth)
	{
		_write_line(lttng::format(
			"{}{}",
			_prefix_with_bullet(depth, lttng::mint_format("[-]{}[/]", _bullet_char())),
			block_n.title()));

		for (const auto& line : block_n.lines()) {
			_write_line(
				_prefix_with_bullet(
					depth + 1,
					lttng::mint_format("[-]{}[/]",
							   locale_supports_utf8() ? "┆" : ":")) +
				line);
		}
	}

	/*
	 * Renders the group node `group_n`.
	 */
	void _render_group(const group_node& group_n, const unsigned int depth)
	{
		const auto bullet = [&] {
			switch (group_n.type()) {
			case group_node::type::ENABLED:
				return lttng::mint_format("[g!*]{}[/]",
							  locale_supports_utf8() ? "✔" : "+");
			case group_node::type::DISABLED:
				return lttng::mint_format("[r!*]{}[/]",
							  locale_supports_utf8() ? "×" : "x");
			case group_node::type::ACTIVE:
				return lttng::mint_format("[g!*]{}[/]",
							  locale_supports_utf8() ? "▶" : ">");
			case group_node::type::INACTIVE:
				return lttng::mint_format("[r!*]{}[/]",
							  locale_supports_utf8() ? "◼" : "#");
			case group_node::type::MAIN:
				return lttng::mint_format("[c!*]{}[/]", _bullet_char());
			case group_node::type::DEFAULT:
				return lttng::mint_format("[-]{}[/]", _bullet_char());
			default:
				std::abort();
			}
		}();

		_write_line([&] {
			auto line = _prefix_with_bullet(depth, bullet) + group_n.title();

			/* Append tags if any */
			if (!group_n.tags().empty()) {
				for (const auto& tag : group_n.tags()) {
					line += lttng::mint_format(" [-]{}[/]{}[-]{}[/]",
								   tag_open_char(),
								   tag,
								   tag_close_char());
				}
			}

			return line;
		}());

		_render_children(group_n, depth);
	}

	/*
	 * Renders the children of `n`.
	 */
	void _render_children(const node& n, const unsigned int depth)
	{
		auto is_first = true;

		for (const auto& child_node : n.children()) {
			_render_node(*child_node, depth + 1, is_first);
			is_first = false;
		}
	}

private:
	/* Current output stream */
	std::ostream *_cur_os;
	bool _is_compact;
	bool _no_truncate;
	bool _pending_empty_line;
};

/*
 * Returns the maximum length of names in the collection `collection`.
 *
 * `get_length_func` is a callable which must return the length of an
 * item in `collection`.
 */
template <typename CollectionType, typename GetLengthFuncType>
std::size_t max_name_length(const CollectionType& collection, GetLengthFuncType&& get_length_func)
{
	std::size_t max_len = 0;

	for (const auto& item : collection) {
		max_len = std::max(max_len, get_length_func(item));
	}

	return max_len;
}

/*
 * Returns a padding string for alignment, if needed.
 */
std::string padding_string(const std::size_t max_len, const std::size_t current_len)
{
	if (max_len > current_len) {
		return std::string(max_len - current_len, ' ');
	}

	return std::string();
}

/*
 * Creates a block node from the fields of the UST
 * tracepoint `tracepoint`.
 *
 * Returns `nullptr` if there's no fields.
 */
std::unique_ptr<node> field_block_node_from_tracepoint(const lttng::cli::ust_tracepoint& tracepoint)
{
	auto& fields = tracepoint.fields();

	if (fields.empty()) {
		return nullptr;
	}

	/* Create field lines */
	std::vector<std::string> field_lines;

	for (const auto& field : fields) {
		if (field.name().len() == 0) {
			continue;
		}

		field_lines.emplace_back(lttng::mint_format(
			"`[!]{}[/]`:{} {}",
			field.name(),
			padding_string(max_name_length(fields,
						       [](const lttng::cli::tracepoint_field& f) {
							       return f.name().len();
						       }),
				       field.name().len()),
			[&] {
				auto type_str = lttng::mint_format("[b*]{}[/]", [&] {
					switch (field.type()) {
					case LTTNG_EVENT_FIELD_INTEGER:
						return "Integer";
					case LTTNG_EVENT_FIELD_ENUM:
						return "Enumeration";
					case LTTNG_EVENT_FIELD_FLOAT:
						return "Floating point number";
					case LTTNG_EVENT_FIELD_STRING:
						return "String";
					case LTTNG_EVENT_FIELD_OTHER:
					default:
						return "Unknown";
					}
				}());

				/* `No write` indicator if applicable */
				if (field.is_no_write()) {
					type_str += lttng::mint(" ([m!]no write[/])");
				}

				return type_str;
			}()));
	}

	if (field_lines.empty()) {
		return nullptr;
	}

	return make_block_node_underlined_title("Fields", std::move(field_lines));
}

/*
 * Creates a node from the UST tracepoint `tracepoint`, including field
 * nodes if `with_fields` is true.
 */
std::unique_ptr<node>
node_from_ust_or_java_python_instrumentation_point(const lttng::cli::ust_tracepoint& tracepoint,
						   const bool with_fields)
{
	return make_group_node(
		lttng::mint_format(
			"`[!y]{}[/]`{}",
			tracepoint.name(),
			[&] {
				if (tracepoint.log_level() != -1) {
					return lttng::mint_format(
						" [-]{}[/] Log level: [!]{}[/] ([!-]{}[/])",
						locale_supports_utf8() ? "—" : "-",
						mi_lttng_loglevel_string(tracepoint.log_level(),
									 LTTNG_DOMAIN_UST),
						tracepoint.log_level());
				}

				return std::string();
			}()),
		[&] {
			node_list children;

			/* Fields block if requested */
			if (with_fields) {
				if (auto field_node =
					    field_block_node_from_tracepoint(tracepoint)) {
					children.emplace_back(std::move(field_node));
				}
			}

			return children;
		}(),
		group_node::type::DEFAULT);
}

/*
 * Creates a node from the Java/Python logger `logger`.
 */
std::unique_ptr<node>
node_from_ust_or_java_python_instrumentation_point(const lttng::cli::java_python_logger& logger,
						   bool)
{
	return make_group_node(lttng::mint_format("`[!y]{}[/]`", logger.name()));
}

/*
 * Creates a node containing all Linux kernel tracepoints.
 *
 * Returns `nullptr` if there's none.
 */
std::unique_ptr<node> node_from_kernel_tracepoints()
{
	const lttng::cli::kernel_tracepoint_set tracepoints;

	if (tracepoints.is_empty()) {
		return nullptr;
	}

	return make_group_node_underlined_title("Linux kernel tracepoints", [&] {
		node_list children;

		for (const auto& tracepoint : tracepoints) {
			children.emplace_back(make_group_node(
				lttng::mint_format("`[y!]{}[/]`", tracepoint.name())));
		}

		return children;
	}());
}

/*
 * Creates a node containing all Linux kernel system calls.
 *
 * Returns `nullptr` if there's none.
 */
std::unique_ptr<node> node_from_kernel_syscalls()
{
	const lttng::cli::kernel_syscall_set syscalls;

	if (syscalls.is_empty()) {
		return nullptr;
	}

	return make_group_node_underlined_title("Linux kernel system calls", [&] {
		node_list children;

		for (const auto& syscall : syscalls) {
			const auto bitness_str = [&] {
				if (syscall.is_32_bit() && syscall.is_64_bit()) {
					return lttng::mint_format(
						"[-]{0}[/][!]32-bit[/][-]{1}[/] [-]{0}[/][!]64-bit[/][-]{1}[/]",
						tag_open_char(),
						tag_close_char());
				} else if (syscall.is_32_bit()) {
					return lttng::mint_format("[-]{}[/][!]32-bit[/][-]{}[/]",
								  tag_open_char(),
								  tag_close_char());
				} else if (syscall.is_64_bit()) {
					return lttng::mint_format(
						"         [-]{}[/][!]64-bit[/][-]{}[/]",
						tag_open_char(),
						tag_close_char());
				}

				return std::string();
			}();

			children.emplace_back(make_group_node(
				lttng::mint_format(
					"`[!y]{}[/]`{}{}",
					syscall.name(),
					bitness_str.empty() ?
						std::string() :
						padding_string(
							max_name_length(
								syscalls,
								[](const lttng::cli::kernel_syscall&
									   sc) {
									return sc.name().len();
								}) +
								1,
							syscall.name().len()),
					bitness_str),
				{},
				group_node::type::DEFAULT));
		}

		return children;
	}());
}

/*
 * Creates a node from the set of instrumentation points `instr_points`
 * grouped by PID, including UST tracepoint fields if `with_fields`
 * is true.
 *
 * Returns `nullptr` if there's none.
 */
template <typename InstrumentationPointSetType>
std::unique_ptr<node>
node_from_pid_grouped_instrumentation_points(const InstrumentationPointSetType& instr_points,
					     const char *const group_title,
					     const bool with_fields)
{
	if (instr_points.is_empty()) {
		return nullptr;
	}

	return make_group_node_underlined_title(group_title, [&] {
		node_list children;
		pid_t cur_pid = 0;
		std::string cur_pid_line;
		node_list pid_children;

		for (const auto& instr_point : instr_points) {
			if (cur_pid != instr_point.pid()) {
				/* New PID detected: finalize previous PID group if any */
				if (!pid_children.empty()) {
					children.emplace_back(
						make_group_node(std::move(cur_pid_line),
								std::move(pid_children),
								group_node::type::MAIN));
					pid_children.clear();
				}

				/* Start new PID group */
				cur_pid = instr_point.pid();
				cur_pid_line =
					lttng::mint_format("[c]Process [!*]{}[/][/]", cur_pid);

				if (const auto cmdline = instr_point.cmdline()) {
					cur_pid_line += lttng::mint_format("[c]:[/] `[m*!]{}[/]`",
									   *cmdline);
				}
			}

			pid_children.emplace_back(
				node_from_ust_or_java_python_instrumentation_point(instr_point,
										   with_fields));
		}

		/* Finalize the last PID group */
		if (!pid_children.empty()) {
			children.emplace_back(make_group_node(
				cur_pid_line, std::move(pid_children), group_node::type::MAIN));
		}

		return children;
	}());
}

/*
 * Creates a node containing all UST tracepoints, grouped by PID,
 * including UST tracepoint fields if `with_fields` is true.
 *
 * Returns `nullptr` if there's none.
 */
std::unique_ptr<node> nodes_from_ust_tracepoints(const bool with_fields)
{
	return node_from_pid_grouped_instrumentation_points(
		lttng::cli::ust_tracepoint_set(), "User space tracepoints", with_fields);
}

/*
 * Creates a node containing all Java/Python loggers of `domain_type`,
 * grouped by PID.
 *
 * Returns `nullptr` if there's none.
 */
std::unique_ptr<node> nodes_from_java_python_loggers(const lttng_domain_type domain_type)
{
	return node_from_pid_grouped_instrumentation_points(
		lttng::cli::java_python_logger_set(domain_type),
		[&] {
			switch (domain_type) {
			case LTTNG_DOMAIN_JUL:
				return "`java.util.logging` (JUL) loggers";
			case LTTNG_DOMAIN_LOG4J:
				return "Apache log4j 1.x loggers";
			case LTTNG_DOMAIN_LOG4J2:
				return "Apache  Log4j 2 loggers";
			case LTTNG_DOMAIN_PYTHON:
				return "Python loggers";
			default:
				std::abort();
			}
		}(),
		false);
}

/*
 * Returns the event rule group node tags from the
 * event rule `event_rule`.
 */
std::vector<std::string>
event_rule_node_tags_from_event_rule(const lttng::cli::event_rule& event_rule,
				     const lttng_domain_type domain_type)
{
	std::vector<std::string> tags;

	/* Instrumentation point type */
	if (domain_type == LTTNG_DOMAIN_KERNEL) {
		tags.emplace_back(lttng::mint_format("[!]{}[/]", [&] {
			switch (event_rule.type()) {
			case LTTNG_EVENT_TRACEPOINT:
				return "Tracepoint";
			case LTTNG_EVENT_PROBE:
				return "Linux kprobe";
			case LTTNG_EVENT_FUNCTION:
				return "Linux kretprobe";
			case LTTNG_EVENT_SYSCALL:
				return "Linux system call";
			case LTTNG_EVENT_USERSPACE_PROBE:
				return "Linux uprobe";
			default:
				std::abort();
			}
		}()));
	}

	return tags;
}

/*
 * Returns an optional probe location property from the
 * event rule `event_rule`.
 */
nonstd::optional<property>
probe_location_property_from_event_rule(const lttng::cli::event_rule& event_rule)
{
	static constexpr auto title = "Probe location";

	if (event_rule.type() == LTTNG_EVENT_PROBE || event_rule.type() == LTTNG_EVENT_FUNCTION) {
		const auto symbol_name = event_rule.as_linux_kprobe().symbol_name();
		const auto address = event_rule.as_linux_kprobe().address();
		const auto offset = event_rule.as_linux_kprobe().offset();

		if (symbol_name.len() > 0) {
			if (offset > 0) {
				return make_raw_property(title,
							 lttng::mint_format("[!]{}[/]+[!]{:#x}[/]",
									    symbol_name,
									    offset));
			} else {
				return make_literal_string_property(title, symbol_name);
			}
		} else if (address > 0) {
			return make_string_property(title, lttng::format("[!]{:#x}[/]", address));
		}
	} else if (event_rule.type() == LTTNG_EVENT_USERSPACE_PROBE) {
		const auto location = event_rule.as_linux_uprobe().location();

		if (location) {
			if (location->type() == LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION) {
				const auto func_location = location->as_function();

				return make_raw_property(
					title,
					lttng::mint_format("elf:[!]{}[/]:[!]{}[/]",
							   func_location.binary_path(),
							   func_location.function_name()));
			} else if (location->type() ==
				   LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT) {
				const auto tp_location = location->as_tracepoint();

				return make_raw_property(
					title,
					lttng::mint_format("sdt:[!]{}[/]:[!]{}[/]:[!]{}[/]",
							   tp_location.binary_path(),
							   tp_location.provider_name(),
							   tp_location.probe_name()));
			}
		}
	}

	return nonstd::nullopt;
}

/*
 * Returns the event rule group node children from the
 * event rule `event_rule`.
 */
node_list event_rule_node_children_from_event_rule(const lttng::cli::event_rule& event_rule,
						   const lttng_domain_type domain_type)
{
	property_set properties;

	/* Filter string */
	{
		const auto filter_expr = event_rule.filter_expression();

		if (filter_expr && filter_expr.len() > 0) {
			properties.emplace(make_literal_string_property("Filter", filter_expr));
		}
	}

	/* Log level rule */
	if (event_rule.type() == LTTNG_EVENT_TRACEPOINT && is_ust_or_agent_domain(domain_type)) {
		auto& spec_event_rule = static_cast<
			const lttng::cli::ust_tracepoint_or_java_python_logger_event_rule&>(
			event_rule);

		if (spec_event_rule.log_level_type() != LTTNG_EVENT_LOGLEVEL_ALL &&
		    spec_event_rule.log_level() != -1) {
			properties.emplace(make_raw_property(
				"Log level",
				lttng::mint_format(
					"{} [!]{}[/] ([!]{}[/])",
					spec_event_rule.log_level_type() ==
							LTTNG_EVENT_LOGLEVEL_RANGE ?
						"As severe as" :
						"Exactly",
					mi_lttng_loglevel_string(spec_event_rule.log_level(),
								 domain_type),
					spec_event_rule.log_level())));
		}
	}

	/* Instrumentation point name exclusions */
	if (event_rule.type() == LTTNG_EVENT_TRACEPOINT && domain_type == LTTNG_DOMAIN_UST) {
		const auto exclusions = event_rule.as_ust_tracepoint().exclusions();

		if (!exclusions.empty()) {
			std::string exclusions_str;
			auto first = true;

			for (const auto& exclusion : exclusions) {
				if (!first) {
					exclusions_str += ", ";
				}

				first = false;
				exclusions_str += lttng::mint_format("`[!]{}[/]`", exclusion);
			}

			properties.emplace(
				make_raw_property("Tracepoint name exclusions", exclusions_str));
		}
	}

	/* Probe location */
	if (auto probe_location_prop = probe_location_property_from_event_rule(event_rule)) {
		properties.emplace(std::move(*probe_location_prop));
	}

	node_list children;

	/* Add property list node if there are any properties */
	if (!properties.empty()) {
		children.emplace_back(make_property_set_node(std::move(properties)));
	}

	return children;
}

/*
 * Creates a node from the event rule `event_rule`.
 */
std::unique_ptr<node> node_from_event_rule(const lttng::cli::event_rule& event_rule,
					   const lttng_domain_type domain_type)
{
	return make_group_node(
		lttng::mint_format("[c]Event rule `[!*]{}[/]`[/]", event_rule.name()),
		event_rule_node_children_from_event_rule(event_rule, domain_type),
		event_rule.is_enabled() ? group_node::type::ENABLED : group_node::type::DISABLED,
		event_rule_node_tags_from_event_rule(event_rule, domain_type));
}

/* List of (process attribute, process attribute tracker) pairs */
using attr_tracker_list =
	std::vector<std::pair<lttng_process_attr, lttng::cli::process_attr_tracker>>;

/*
 * Formats the inclusion set `inclusion_set` into wrapped lines.
 */
std::vector<std::string>
format_inclusion_set_lines(const std::set<lttng::cli::process_attr_value>& inclusion_set)
{
	std::vector<std::string> lines;
	std::string current_line("Allow only");

	for (auto value_it = inclusion_set.begin(); value_it != inclusion_set.end(); ++value_it) {
		/* Format the value */
		const auto formatted_value = [&] {
			std::string ret(" ");

			switch (value_it->type()) {
			case LTTNG_PROCESS_ATTR_VALUE_TYPE_PID:
				ret += lttng::mint_format("[!]{}[/]", value_it->pid());
				break;
			case LTTNG_PROCESS_ATTR_VALUE_TYPE_UID:
				ret += lttng::mint_format("[!]{}[/]", value_it->uid());
				break;
			case LTTNG_PROCESS_ATTR_VALUE_TYPE_GID:
				ret += lttng::mint_format("[!]{}[/]", value_it->gid());
				break;
			case LTTNG_PROCESS_ATTR_VALUE_TYPE_USER_NAME:
				ret += lttng::mint_format("`[!]{}[/]`", value_it->user_name());
				break;
			case LTTNG_PROCESS_ATTR_VALUE_TYPE_GROUP_NAME:
				ret += lttng::mint_format("`[!]{}[/]`", value_it->group_name());
				break;
			default:
				std::abort();
			}

			/* Add comma if not the last value */
			if (std::next(value_it) != inclusion_set.end()) {
				ret += ",";
			}

			return ret;
		}();

		/*
		 * Check if adding this value would exceed the
		 * available width.
		 *
		 * 21 is an indentation of 8 spaces + the length
		 * of `Virtual PID: `.
		 */
		if (!current_line.empty() &&
		    lttng::mint_escape_ansi(current_line + formatted_value).length() >
			    term_columns() - 21) {
			/* Save current line and start a new one */
			lines.emplace_back(std::move(current_line));

			/* Start new line _without_ the space prefix */
			current_line = formatted_value.substr(1);
		} else {
			current_line += formatted_value;
		}
	}

	/* Add the last line if not empty */
	if (!current_line.empty()) {
		lines.emplace_back(std::move(current_line));
	}

	return lines;
}

constexpr auto process_filter_title = "Process filter";
constexpr auto allow_none_str = "Allow none";

/*
 * Creates a process filter block node with detailed information from
 * the tracker `trackers`.
 */
std::unique_ptr<node> process_filter_node_from_trackers(const attr_tracker_list& trackers)
{
	return make_block_node_underlined_title(process_filter_title, [&] {
		std::vector<std::string> lines;

		for (const auto& attr_tracker_pair : trackers) {
			const auto policy = attr_tracker_pair.second.tracking_policy();

			/* 12 is the length of `Virtual PID:` */
			std::string line =
				lttng::format("{:<12} ", [&attr_tracker_pair]() -> std::string {
					switch (attr_tracker_pair.first) {
					case LTTNG_PROCESS_ATTR_PROCESS_ID:
						return "PID";
					case LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID:
						return "Virtual PID";
					case LTTNG_PROCESS_ATTR_USER_ID:
						return "UID";
					case LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID:
						return "Virtual UID";
					case LTTNG_PROCESS_ATTR_GROUP_ID:
						return "GID";
					case LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID:
						return "Virtual GID";
					default:
						std::abort();
					}
				}() + ":");

			if (policy == LTTNG_TRACKING_POLICY_INCLUDE_ALL) {
				line += lttng::mint("[!]Allow all[/]");
				lines.emplace_back(std::move(line));
			} else if (policy == LTTNG_TRACKING_POLICY_EXCLUDE_ALL) {
				line += lttng::mint_format("[!*m]{}[/]", allow_none_str);
				lines.emplace_back(std::move(line));
			} else {
				LTTNG_ASSERT(policy == LTTNG_TRACKING_POLICY_INCLUDE_SET);

				const auto inclusion_set = attr_tracker_pair.second.inclusion_set();

				if (!inclusion_set || inclusion_set->empty()) {
					line += lttng::mint_format("[!*m]{}[/]", allow_none_str);
				} else {
					const auto value_lines =
						format_inclusion_set_lines(*inclusion_set);

					/* Add first line without prefix indentation */
					auto line_it = value_lines.begin();

					line += *line_it;
					lines.emplace_back(std::move(line));
					++line_it;

					/* Add continuation lines with proper indentation */
					for (; line_it != value_lines.end(); ++line_it) {
						/* 13 is the length of `Virtual PID: ` */
						lines.emplace_back(std::string(13, ' ') + *line_it);
					}

					continue;
				}
			}
		}

		return lines;
	}());
}

/*
 * Creates a process filter node from the domain `domain`.
 *
 * Returns `nullptr` if there's none.
 */
std::unique_ptr<node> process_filter_node_from_domain(const lttng::cli::domain& domain)
{
	/* Only kernel and UST domains support process attribute tracking */
	if (domain.type() != LTTNG_DOMAIN_KERNEL && domain.type() != LTTNG_DOMAIN_UST) {
		return nullptr;
	}

	/* Get all trackers for this domain */
	const auto trackers = [&] {
		attr_tracker_list ret;

		if (domain.type() == LTTNG_DOMAIN_KERNEL) {
			const auto kernel_domain = domain.as_kernel();

			ret.emplace_back(LTTNG_PROCESS_ATTR_PROCESS_ID,
					 kernel_domain.process_id_tracker());
			ret.emplace_back(LTTNG_PROCESS_ATTR_USER_ID,
					 kernel_domain.user_id_tracker());
			ret.emplace_back(LTTNG_PROCESS_ATTR_GROUP_ID,
					 kernel_domain.group_id_tracker());
			ret.emplace_back(LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID,
					 kernel_domain.virtual_process_id_tracker());
			ret.emplace_back(LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID,
					 kernel_domain.virtual_user_id_tracker());
			ret.emplace_back(LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID,
					 kernel_domain.virtual_group_id_tracker());
		} else {
			const auto ust_domain = domain.as_ust();

			ret.emplace_back(LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID,
					 ust_domain.virtual_process_id_tracker());
			ret.emplace_back(LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID,
					 ust_domain.virtual_user_id_tracker());
			ret.emplace_back(LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID,
					 ust_domain.virtual_group_id_tracker());
		}

		return ret;
	}();

	/* Check if all trackers have the same policy */
	{
		auto all_include_all = true;
		auto all_exclude_all = true;

		for (const auto& attr_tracker_pair : trackers) {
			const auto policy = attr_tracker_pair.second.tracking_policy();

			if (policy != LTTNG_TRACKING_POLICY_INCLUDE_ALL) {
				all_include_all = false;
			}

			if (policy == LTTNG_TRACKING_POLICY_INCLUDE_SET) {
				const auto inclusion_set = attr_tracker_pair.second.inclusion_set();

				if (inclusion_set && !inclusion_set->empty()) {
					all_exclude_all = false;
				}
			} else if (policy != LTTNG_TRACKING_POLICY_EXCLUDE_ALL) {
				all_exclude_all = false;
			}
		}

		/* Scenario 1: all trackers allow all */
		if (all_include_all) {
			property_set properties;
			properties.emplace(make_string_property(process_filter_title, "Allow all"));
			return make_property_set_node(std::move(properties));
		}

		/* Scenario 2: all trackers allow none */
		if (all_exclude_all) {
			property_set properties;
			properties.emplace(make_raw_property(process_filter_title,
							     lttng::mint_format("[m!*]{}[/]",
										allow_none_str)));
			return make_property_set_node(std::move(properties));
		}
	}

	/* Scenario 3: mixed policies */
	return process_filter_node_from_trackers(trackers);
}

/*
 * Returns a new string with `str` repeated `count` times.
 */
std::string repeat_string(const std::string& str, const std::size_t count)
{
	std::string result;

	result.reserve(str.length() * count);

	for (std::size_t i = 0; i < count; ++i) {
		result += str;
	}

	return result;
}

/*
 * Type of memory usage line.
 */
enum class memory_usage_line_type {
	/* Grand total */
	TOTAL,

	/* Each data stream info set */
	SET,

	/* All CPUs */
	CPU,
};

/*
 * Returns a string representing a progress bar with `length`
 * characters, filled according to the ratio of `value` on `max`,
 * for a line of type `type`.
 */
std::string draw_progress_bar(std::uint64_t value,
			      std::uint64_t max,
			      const std::size_t length,
			      const memory_usage_line_type type)
{
	static const std::string base_mint_fmt("{}[!]{}[/][-]{}[/]{}");
	static const auto set_mint_fmt = lttng::format("[b*]{}[/]", base_mint_fmt);
	static const auto total_mint_fmt = lttng::format("[y]{}[/]", base_mint_fmt);

	value = value > max ? max : value;

	if (max == 0) {
		max = std::numeric_limits<std::uint64_t>::max();
	}

	const auto ratio = static_cast<double>(value) / static_cast<double>(max);
	const auto bar_length = length - 2;
	const auto filled_length = static_cast<std::size_t>(ratio * bar_length);

	auto& mint_fmt = [&]() -> const std::string& {
		if (type == memory_usage_line_type::TOTAL) {
			return total_mint_fmt;
		} else if (type == memory_usage_line_type::SET) {
			return set_mint_fmt;
		} else {
			LTTNG_ASSERT(type == memory_usage_line_type::CPU);
			return base_mint_fmt;
		}
	}();

	return lttng::mint_format(mint_fmt,
				  locale_supports_utf8() ? "❲" : "[",
				  repeat_string(locale_supports_utf8() ? "●" : "#", filled_length),
				  repeat_string(locale_supports_utf8() ? "┄" : "-",
						bar_length - filled_length),
				  locale_supports_utf8() ? "❳" : "]");
}

/*
 * Returns a string like `  31.45 KiB /   32.00 MiB` from `value`, with
 * right-aligned whole parts and units, stylizing for the line
 * type `type`.
 */
std::string format_memory_usage(const std::uint64_t value,
				const std::uint64_t max,
				const memory_usage_line_type type)
{
	static const std::string base_mint_fmt("[!]{:>7.2f}[/] {:>3} / [!]{:>7.2f}[/] {:>3}");
	static const auto set_mint_fmt = lttng::format("[b*]{}[/]", base_mint_fmt);
	static const auto total_mint_fmt = lttng::format("[y]{}[/]", base_mint_fmt);
	const auto value_pair = utils_value_unit_from_size(value);
	const auto max_pair = utils_value_unit_from_size(max);

	auto& mint_fmt = [&]() -> const std::string& {
		if (type == memory_usage_line_type::TOTAL) {
			return total_mint_fmt;
		} else if (type == memory_usage_line_type::SET) {
			return set_mint_fmt;
		} else {
			LTTNG_ASSERT(type == memory_usage_line_type::CPU);
			return base_mint_fmt;
		}
	}();

	return lttng::mint_format(
		mint_fmt, value_pair.first, value_pair.second, max_pair.first, max_pair.second);
}

/*
 * Draws a memory usage line with a prefix, a progress bar, and a
 * formatted usage.
 *
 * Example:
 *
 *     For UID 1000 (32-bit): ████████░░░░░░░░░░░░░░░░    8.13 MiB /   32.00 MiB
 *
 * Doesn't include a progress bar if the terminal width is too narrow.
 */
std::string draw_memory_usage_line(const std::string& prefix,
				   const std::uint64_t usage,
				   const std::uint64_t max_usage,
				   const unsigned int indent_level,
				   const memory_usage_line_type type)
{
	if (term_columns() <= 72) {
		return lttng::format("{}: {}", prefix, format_memory_usage(usage, max_usage, type));
	}

	/* 25 is the fixed length of what format_memory_usage() returns */
	const auto available_width = std::min(
		static_cast<unsigned int>(term_columns() - indent_level), 100U - indent_level);
	const auto bar_width = available_width - lttng::mint_escape_ansi(prefix).length() - 3 - 25;

	return lttng::format("{}: {} {}",
			     prefix,
			     draw_progress_bar(usage, max_usage, bar_width, type),
			     format_memory_usage(usage, max_usage, type));
}

/*
 * Creates a memory usage node from the channel `channel`.
 *
 * Returns `nullptr` if memory usage information is not available (Linux
 * kernel channel or UST channel without any created ring buffer).
 */
std::unique_ptr<node> memory_usage_node_from_channel(const lttng::cli::channel& channel,
						     const list_cmd_mem_usage_mode mode)
{
	/* Only UST/Java/Python channels have memory usage information */
	if (channel.domain_type() == LTTNG_DOMAIN_KERNEL) {
		return nullptr;
	}

	const auto ds_info_sets = channel.as_ust_or_java_python().data_stream_infos();

	if (ds_info_sets.is_empty()) {
		return nullptr;
	}

	const auto total_usage_line_solo =
		draw_memory_usage_line("Memory usage",
				       ds_info_sets.memory_usage_bytes(),
				       ds_info_sets.max_memory_usage_bytes(),
				       10,
				       memory_usage_line_type::CPU);

	if (mode == list_cmd_mem_usage_mode::TOTAL) {
		return make_group_node(total_usage_line_solo);
	}

	/* Build detailed lines */
	std::vector<std::string> lines;

	for (const auto& ds_info_set : ds_info_sets) {
		lines.emplace_back(draw_memory_usage_line(
			[&] {
				std::string prefix;

				if (const auto uid = ds_info_set.uid()) {
					prefix =
						lttng::mint_format("For [b*]UID [!]{}[/][/]", *uid);
				} else if (const auto pid = ds_info_set.pid()) {
					prefix =
						lttng::mint_format("For [b*]PID [!]{}[/][/]", *pid);
				} else {
					std::abort();
				}

				if (const auto app_bitness = ds_info_set.app_bitness()) {
					prefix += lttng::mint_format(" ([!]{}[/])", [&] {
						if (*app_bitness == LTTNG_APP_BITNESS_32) {
							return "32-bit";
						} else {
							LTTNG_ASSERT(*app_bitness ==
								     LTTNG_APP_BITNESS_64);
							return "64-bit";
						}
					}());
				}

				return prefix;
			}(),
			ds_info_set.memory_usage_bytes(),
			ds_info_set.max_memory_usage_bytes(),
			12,
			memory_usage_line_type::SET));

		if (mode == list_cmd_mem_usage_mode::FULL &&
		    (ds_info_set.size() > 1 ||
		     (ds_info_set.size() == 1 && ds_info_set.begin()->cpu_id()))) {
			for (const auto& ds_info : ds_info_set) {
				LTTNG_ASSERT(ds_info.cpu_id());

				lines.emplace_back(draw_memory_usage_line(
					lttng::mint_format("  CPU [!]{:>3}[/]", *ds_info.cpu_id()),
					ds_info.memory_usage_bytes(),
					ds_info.max_memory_usage_bytes(),
					12,
					memory_usage_line_type::CPU));
			}
		}
	}

	if (lines.empty()) {
		return make_group_node(total_usage_line_solo);
	}

	return make_block_node(draw_memory_usage_line(lttng::mint("[_]Memory usage[/]"),
						      ds_info_sets.memory_usage_bytes(),
						      ds_info_sets.max_memory_usage_bytes(),
						      10,
						      memory_usage_line_type::TOTAL),
			       std::move(lines));
}

std::string plural(const char *const noun, const std::size_t count)
{
	return std::string(noun) + (count != 1 ? "s" : "");
}

/*
 * Creates a node from the channel `channel` within the recording
 * session `session`.
 */
std::unique_ptr<node> node_from_channel(const lttng::cli::session& session,
					const lttng::cli::channel& channel,
					const list_cmd_mem_usage_mode mem_usage)
{
	node_list children;

	/* Basic properties */
	{
		property_set properties;

		properties.emplace(make_string_property("Loss mode",
							channel.is_discard_mode() ?
								"Discard newest event record" :
								"Overwrite oldest sub-buffer"));
		properties.emplace(make_raw_property(
			"Ring buffer configuration",
			lttng::mint_format(
				"[!]{}[/] sub-buffers of [!]{}{}[/]{}",
				channel.sub_buf_count(),
				utils_string_from_size(channel.sub_buf_size()),
				[&] {
					auto alloc_policy = LTTNG_CHANNEL_ALLOCATION_POLICY_PER_CPU;

					if (channel.domain_type() != LTTNG_DOMAIN_KERNEL) {
						alloc_policy = channel.as_ust_or_java_python()
								       .allocation_policy();
					}

					return alloc_policy ==
							LTTNG_CHANNEL_ALLOCATION_POLICY_PER_CPU ?
						" per CPU" :
						"";
				}(),
				[&]() -> std::string {
					if (channel.domain_type() == LTTNG_DOMAIN_KERNEL) {
						return "";
					}

					std::string ret;

					if (channel.as_ust_or_java_python().allocation_policy() ==
					    LTTNG_CHANNEL_ALLOCATION_POLICY_PER_CPU) {
						/*
						 * We wrote `per CPU` before,
						 * and it's clearer with a
						 * comma between this and the
						 * ownership model.
						 */
						ret += ',';
					}

					if (channel.as_ust_or_java_python()
						    .buffer_ownership_model() ==
					    LTTNG_BUFFER_PER_UID) {
						ret += lttng::mint(" [!]per Unix user[/]");
					} else {
						ret += lttng::mint(" [!]per process[/]");
					}

					return ret;
				}())));

		if (channel.max_trace_file_size() > 0) {
			properties.emplace(make_size_property("Max. trace file size",
							      channel.max_trace_file_size()));
		}

		if (channel.max_trace_file_count() > 0) {
			properties.emplace(make_size_property("Max. trace file count",
							      channel.max_trace_file_count()));
		}

		properties.emplace(make_string_property(
			"Preallocation policy",
			channel.domain_type() == LTTNG_DOMAIN_KERNEL ||
					channel.as_ust_or_java_python().preallocation_policy() ==
						LTTNG_CHANNEL_PREALLOCATION_POLICY_PREALLOCATE ?
				"Preallocate" :
				"On demand"));

		if (channel.domain_type() == LTTNG_DOMAIN_KERNEL) {
			/* Linux kernel-specific properties */
			properties.emplace(make_string_property("Output type",
								channel.as_kernel().output_type() ==
										LTTNG_EVENT_SPLICE ?
									"splice()" :
									"mmap()"));
		} else {
			/* UST-specific properties */
			const auto ust_channel = channel.as_ust_or_java_python();

			if (const auto blocking_timeout = ust_channel.blocking_timeout_us()) {
				properties.emplace(make_period_property("Blocking timeout",
									*blocking_timeout));
			}

			{
				static constexpr auto title = "Auto. memory reclaim policy";

				if (const auto max_age =
					    ust_channel.automatic_memory_reclaim_maximal_age_us()) {
					if (*max_age == 0) {
						properties.emplace(make_string_property(
							title, "When consumed"));
					} else {
						properties.emplace(make_raw_property(
							title,
							lttng::format("When older than {}",
								      format_period(*max_age))));
					}
				} else {
					properties.emplace(make_string_property(title, "None"));
				}
			}
		}

		children.emplace_back(make_property_set_node(std::move(properties)));
	}

	/* Timers */
	{
		property_set timer_properties;

		timer_properties.emplace(
			make_period_property("Switch timer", channel.switch_timer_period_us()));
		timer_properties.emplace(
			make_period_property("Read timer", channel.read_timer_period_us()));
		timer_properties.emplace(
			make_period_property("Monitor timer", channel.monitor_timer_period_us()));

		if (session.live_timer_period_us()) {
			timer_properties.emplace(make_period_property(
				"Live timer", *session.live_timer_period_us()));
		}

		if (channel.domain_type() != LTTNG_DOMAIN_KERNEL) {
			const auto ust_channel = channel.as_ust_or_java_python();

			if (const auto watchdog_timer = ust_channel.watchdog_timer_period_us()) {
				timer_properties.emplace(
					make_period_property("Watchdog timer", *watchdog_timer));
			}
		}

		node_list timer_children;

		timer_children.emplace_back(make_property_set_node(std::move(timer_properties)));
		children.emplace_back(make_group_node(lttng::mint("[_]Timer periods[/]:"),
						      std::move(timer_children)));
	}

	/* Statistics */
	{
		property_set stats_properties;

		if (channel.is_discard_mode()) {
			stats_properties.emplace(make_count_property(
				"Discarded event records", channel.discarded_event_record_count()));
		} else if (!session.is_snapshot_mode()) {
			/*
			 * The discarded packet count is omitted for recording
			 * sessions in snapshot mode as it's misleading: it would
			 * indicate the number of packets that the consumer couldn't
			 * extract during the course of recording the snapshot.
			 *
			 * It does not have the same meaning as the "regular"
			 * discarded packet count that would result from the
			 * consumer not keeping up with event record production in
			 * an overwrite-mode channel.
			 *
			 * A more interesting statistic would be the number of
			 * packets discarded between the first and last extracted
			 * packets of a given snapshot (which prevents
			 * most analyses).
			 */
			stats_properties.emplace(make_count_property(
				"Discarded packets", channel.discarded_packet_count()));
		}

		auto memory_usage_node = memory_usage_node_from_channel(channel, mem_usage);

		if (!memory_usage_node) {
			/* Use a property to align the value */
			stats_properties.emplace(make_string_property(
				"Memory usage",
				channel.domain_type() == LTTNG_DOMAIN_KERNEL ? "Not available" :
									       "None"));
		}

		node_list stats_children;

		if (!stats_properties.empty()) {
			stats_children.emplace_back(
				make_property_set_node(std::move(stats_properties)));
		}

		if (memory_usage_node) {
			stats_children.emplace_back(std::move(memory_usage_node));
		}

		children.emplace_back(make_group_node(lttng::mint("[_]Statistics[/]:"),
						      std::move(stats_children)));
	}

	/* Event rules */
	std::vector<std::string> tags;

	{
		const auto event_rules = channel.event_rules();

		for (const auto& event_rule : event_rules) {
			children.emplace_back(
				node_from_event_rule(event_rule, channel.domain_type()));
		}

		tags.emplace_back(lttng::mint_format("[y][!]{}[/] {}[/]",
						     event_rules.size(),
						     plural("event rule", event_rules.size())));
	}

	/* Final node */
	return make_group_node(lttng::mint_format("[c]Channel `[!*]{}[/]`[/]", channel.name()),
			       std::move(children),
			       channel.is_enabled() ? group_node::type::ENABLED :
						      group_node::type::DISABLED,
			       std::move(tags));
}

/*
 * Creates a node from the domain `domain` within the recording
 * session `session`.
 */
std::unique_ptr<node> node_from_domain(const lttng::cli::session& session,
				       const lttng::cli::domain& domain,
				       const list_cmd_config& config)
{
	const auto channels = domain.channels();

	std::vector<std::string> tags;
	nonstd::optional<lttng::cli::event_rule_set<lttng::cli::java_python_logger_event_rule>>
		java_python_event_rules;

	/* Build tag based on domain type */
	if (is_agent_domain(domain.type())) {
		/* Java/Python domains: show event rule count */
		java_python_event_rules = domain.as_java_python().event_rules();

		const auto event_rule_count = java_python_event_rules->size();

		tags.emplace_back(lttng::mint_format("[y][!]{}[/] {}[/]",
						     event_rule_count,
						     plural("event rule", event_rule_count)));
	} else {
		/* Kernel/UST domains: show channel count */
		tags.emplace_back(lttng::mint_format(
			"[y][!]{}[/] {}[/]", channels.size(), plural("channel", channels.size())));
	}

	return make_group_node(
		lttng::mint_format("[c]Domain [!*]{}[/][/]",
				   [&] {
					   switch (domain.type()) {
					   case LTTNG_DOMAIN_KERNEL:
						   return "Linux kernel";
					   case LTTNG_DOMAIN_UST:
						   return "User space";
					   case LTTNG_DOMAIN_JUL:
						   return "`java.util.logging` (JUL)";
					   case LTTNG_DOMAIN_LOG4J:
						   return "log4j 1.x";
					   case LTTNG_DOMAIN_LOG4J2:
						   return "Log4j 2";
					   case LTTNG_DOMAIN_PYTHON:
						   return "Python";
					   default:
						   std::abort();
					   }
				   }()),
		[&] {
			node_list children;

			/* Children only if there's a configured session name */
			if (config.session_name) {
				/* Process filter node */
				if (auto filter_node = process_filter_node_from_domain(domain)) {
					children.emplace_back(std::move(filter_node));
				}

				/* Channel nodes if requested */
				if (!config.domain) {
					for (const auto& channel : channels) {
						if (config.channel_name &&
						    channel.name() != *config.channel_name) {
							continue;
						}

						children.emplace_back(node_from_channel(
							session, channel, config.mem_usage));
					}
				}

				/* Event rules for Java/Python domains (no direct channels) */
				if (is_agent_domain(domain.type())) {
					LTTNG_ASSERT(java_python_event_rules);

					for (const auto& event_rule : *java_python_event_rules) {
						children.emplace_back(node_from_event_rule(
							event_rule, domain.type()));
					}
				}
			}

			return children;
		}(),
		group_node::type::MAIN,
		std::move(tags));
}

/*
 * Creates a node from the recording session `session`.
 */
std::unique_ptr<node> node_from_session(const lttng::cli::session& session,
					const list_cmd_config& config)
{
	const auto cur_session_name =
		lttng::make_unique_wrapper<char, lttng::memory::free>(get_session_name_quiet());

	return make_group_node(
		cur_session_name && std::strcmp(cur_session_name.get(), session.name()) == 0 ?
			lttng::mint_format("[c_]Recording session `[!*]{}[/]`[/]", session.name()) :
			lttng::mint_format("[c]Recording session `[!*]{}[/]`[/]", session.name()),
		[&] {
			/* Build properties */
			property_set properties;

			/* Automatic rotation schedules */
			{
				const auto schedules = session.rotation_schedules();

				if (!schedules.is_empty()) {
					std::string schedule_str;
					auto first = true;

					for (const auto& schedule : schedules) {
						if (!first) {
							schedule_str += " or ";
						}

						first = false;

						switch (schedule.type()) {
						case LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD:
						{
							schedule_str += lttng::mint_format(
								"when reaching [!]{}[/]",
								utils_string_from_size(
									schedule.as_size()
										.threshold()));
							break;
						}
						case LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC:
						{
							schedule_str += lttng::mint_format(
								"every [!]{}[/]",
								utils_string_from_period(
									schedule.as_periodic()
										.period()));
							break;
						}
						default:
							std::abort();
						}
					}

					schedule_str[0] = std::toupper(schedule_str[0]);
					properties.emplace(make_raw_property(
						"Auto. rotation schedule", schedule_str));
				}
			}

			/* Live timer period */
			if (session.live_timer_period_us()) {
				properties.emplace(make_period_property(
					"Live timer period", *session.live_timer_period_us()));
			}

			/* Output */
			if (session.output() && session.output().len() > 0) {
				static constexpr auto title = "Output";

				if (session.output().startsWith("/")) {
					properties.emplace(make_literal_string_property(
						title, session.output()));
				} else {
					properties.emplace(
						make_string_property(title, session.output()));
				}
			}

			/* Default snapshot output */
			if (session.is_snapshot_mode()) {
				if (const auto snapshot_out = session.default_snapshot_output()) {
					const auto ctrl_uri = snapshot_out->control_url();
					const auto data_uri = snapshot_out->data_url();

					if (ctrl_uri && data_uri && ctrl_uri.len() > 0 &&
					    data_uri.len() > 0 && ctrl_uri == data_uri) {
						/* Both URIs are the same: use a single property */
						properties.emplace(make_literal_string_property(
							"Default snapshot URI", ctrl_uri));
					} else {
						/* Different URIs or only one is set */
						if (ctrl_uri && ctrl_uri.len() > 0) {
							properties.emplace(
								make_literal_string_property(
									"Default snapshot control URI",
									ctrl_uri));
						}

						if (data_uri && data_uri.len() > 0) {
							properties.emplace(
								make_literal_string_property(
									"Default snapshot data URI",
									data_uri));
						}
					}
				}
			}

			/* Shared memory path override */
			if (session.shm_dir_override()) {
				properties.emplace(make_literal_string_property(
					"Shared memory path", *session.shm_dir_override()));
			}

			/* Build children */
			node_list children;

			if (!properties.empty()) {
				children.emplace_back(
					make_property_set_node(std::move(properties)));
			}

			/* Domains */
			if (config.session_name || config.domain) {
				const auto domains = session.domains();

				for (const auto& domain : domains) {
					/*
					 * Filter domains if at least
					 * one domain option is
					 * specified. If no domain
					 * options are specified,
					 * include all domains.
					 */
					if (config.kernel || config.userspace || config.jul ||
					    config.log4j || config.log4j2 || config.python) {
						auto matches = false;

						switch (domain.type()) {
						case LTTNG_DOMAIN_KERNEL:
							matches = config.kernel;
							break;
						case LTTNG_DOMAIN_UST:
							matches = config.userspace;
							break;
						case LTTNG_DOMAIN_JUL:
							matches = config.jul;
							break;
						case LTTNG_DOMAIN_LOG4J:
							matches = config.log4j;
							break;
						case LTTNG_DOMAIN_LOG4J2:
							matches = config.log4j2;
							break;
						case LTTNG_DOMAIN_PYTHON:
							matches = config.python;
							break;
						default:
							break;
						}

						if (!matches) {
							continue;
						}
					}

					children.emplace_back(
						node_from_domain(session, domain, config));
				}
			}

			return children;
		}(),
		session.is_active() ? group_node::type::ACTIVE : group_node::type::INACTIVE,
		[&] {
			std::vector<std::string> ret;

			/* Mode */
			if (session.is_snapshot_mode()) {
				ret.emplace_back(lttng::mint("[y!]Snapshot mode[/]"));
			} else if (session.live_timer_period_us()) {
				ret.emplace_back(lttng::mint("[y!]Live mode[/]"));
			}

			/* Creation time */
			{
				char date_time_str[128];
				const time_t creation_time_t = session.creation_time();

				DIAGNOSTIC_PUSH
				DIAGNOSTIC_IGNORE_FORMAT_NONLITERAL
				if (std::strftime(
					    date_time_str,
					    sizeof(date_time_str),
					    lttng::mint("[y][!]%Y-%m-%d[/] @ [!]%H:%M:%S[/][/]")
						    .data(),
					    std::localtime(&creation_time_t)) != 0) {
					DIAGNOSTIC_POP
					ret.emplace_back(
						lttng::mint_format("Created: {}", date_time_str));
				}
			}

			return ret;
		}());
}

void print_info(const std::string& msg)
{
	lttng::mint_print("[y*!]{}[/]\n", msg);
}

} /* namespace */

void list_human(const list_cmd_config& config)
{
	node_list nodes;

	if (!config.session_name) {
		/*
		 * No session specified: list instrumentation points
		 * or sessions.
		 */
		if (config.kernel || config.userspace || config.jul || config.log4j ||
		    config.log4j2 || config.python) {
			/* Linux Kernel events */
			if (config.kernel) {
				std::unique_ptr<node> node;

				if (config.syscall) {
					node = node_from_kernel_syscalls();
				} else {
					node = node_from_kernel_tracepoints();
				}

				if (node) {
					nodes.emplace_back(std::move(node));
				}
			}

			/* UST tracepoints */
			if (config.userspace) {
				auto node = nodes_from_ust_tracepoints(config.fields);

				if (node) {
					nodes.emplace_back(std::move(node));
				}
			}

			/* Java/Python loggers */
			if (config.jul) {
				auto node = nodes_from_java_python_loggers(LTTNG_DOMAIN_JUL);

				if (node) {
					nodes.emplace_back(std::move(node));
				}
			}

			if (config.log4j) {
				auto node = nodes_from_java_python_loggers(LTTNG_DOMAIN_LOG4J);

				if (node) {
					nodes.emplace_back(std::move(node));
				}
			}

			if (config.log4j2) {
				auto node = nodes_from_java_python_loggers(LTTNG_DOMAIN_LOG4J2);

				if (node) {
					nodes.emplace_back(std::move(node));
				}
			}

			if (config.python) {
				auto node = nodes_from_java_python_loggers(LTTNG_DOMAIN_PYTHON);

				if (node) {
					nodes.emplace_back(std::move(node));
				}
			}

			if (nodes.empty()) {
				print_info("No requested instrumentation points available!");
				return;
			}
		} else {
			/* List all sessions */
			const lttng::cli::session_list sessions;

			if (sessions.is_empty()) {
				print_info("No recording sessions available!");
				return;
			}

			for (const auto& session : sessions) {
				nodes.emplace_back(node_from_session(session, config));
			}
		}
	} else {
		/* List a specific session */
		const lttng::cli::session_list sessions;

		if (const auto session = sessions.find_by_name(config.session_name->c_str())) {
			nodes.emplace_back(node_from_session(*session, config));
		} else {
			LTTNG_THROW_ERROR(lttng::format("Recording session `{}` not found",
							*config.session_name));
		}
	}

	/* Render the nodes, one after the other */
	renderer r(config.style == list_cmd_style::COMPACT, config.no_truncate);
	auto is_first = true;

	for (const auto& node : nodes) {
		if (config.style != list_cmd_style::COMPACT && !is_first) {
			std::cout << '\n';
		}

		r.render(*node, std::cout);
		is_first = false;
	}
}
