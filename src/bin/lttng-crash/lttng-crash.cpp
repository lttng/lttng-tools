/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/binary-view.hpp>
#include <common/common.hpp>
#include <common/compat/endian.hpp>
#include <common/exception.hpp>
#include <common/file-descriptor.hpp>
#include <common/format.hpp>
#include <common/math.hpp>
#include <common/scope-exit.hpp>
#include <common/spawn-viewer.hpp>
#include <common/stream-descriptor.hpp>
#include <common/string-utils/c-string-view.hpp>
#include <common/utils.hpp>

#include <lttng/lttng.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits>
#include <optional>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>
#include <version-git.hpp>
#include <version.hpp>

static_assert(sizeof(off_t) >= sizeof(std::uint64_t), "`off_t` must be at least 64-bit");

#define RB_CRASH_DUMP_ABI_LEN 32

#define RB_CRASH_DUMP_ABI_MAGIC_LEN 16

/*
 * The 128-bit magic number is xor'd in the process data so it does not
 * cause a false positive when searching for buffers by scanning memory.
 * The actual magic number is:
 *   0x17, 0x7B, 0xF1, 0x77, 0xBF, 0x17, 0x7B, 0xF1,
 *   0x77, 0xBF, 0x17, 0x7B, 0xF1, 0x77, 0xBF, 0x17,
 */
#define RB_CRASH_DUMP_ABI_MAGIC_XOR                                                           \
	{                                                                                     \
		0x17 ^ 0xFF, 0x7B ^ 0xFF, 0xF1 ^ 0xFF, 0x77 ^ 0xFF, 0xBF ^ 0xFF, 0x17 ^ 0xFF, \
			0x7B ^ 0xFF, 0xF1 ^ 0xFF, 0x77 ^ 0xFF, 0xBF ^ 0xFF, 0x17 ^ 0xFF,      \
			0x7B ^ 0xFF, 0xF1 ^ 0xFF, 0x77 ^ 0xFF, 0xBF ^ 0xFF, 0x17 ^ 0xFF,      \
	}

namespace {
const char *help_msg =
#ifdef LTTNG_EMBED_HELP
#include <lttng-crash.1.h>
#else
	nullptr
#endif
	;
} /* namespace */

/*
 * Non-static to ensure the compiler does not optimize away the xor.
 */
uint8_t lttng_crash_expected_magic_xor[] = RB_CRASH_DUMP_ABI_MAGIC_XOR;

#define RB_CRASH_ENDIAN		0x1234
#define RB_CRASH_ENDIAN_REVERSE 0x3412

enum lttng_crash_type {
	LTTNG_CRASH_TYPE_UST = 0,
	LTTNG_CRASH_TYPE_KERNEL = 1,
};

/* LTTng ring buffer defines (copied) */

#define HALF_ULONG_BITS(wl) (((wl) *CHAR_BIT) >> 1)

#define SB_ID_OFFSET_SHIFT(wl) (HALF_ULONG_BITS(wl) + 1)
#define SB_ID_OFFSET_COUNT(wl) (1UL << SB_ID_OFFSET_SHIFT(wl))
#define SB_ID_OFFSET_MASK(wl)  (~(SB_ID_OFFSET_COUNT(wl) - 1))
/*
 * LTTng crash ABI 0.0:
 *   - Lowest bit of top word half belongs to noref. Used only for overwrite mode.
 * LTTng crash ABI 1.0:
 *   - Lowest bit of top word half belongs to noref.
 */
#define SB_ID_NOREF_SHIFT(wl) (SB_ID_OFFSET_SHIFT(wl) - 1)
#define SB_ID_NOREF_COUNT(wl) (1UL << SB_ID_NOREF_SHIFT(wl))
#define SB_ID_NOREF_MASK(wl)  SB_ID_NOREF_COUNT(wl)
/*
 * LTTng crash ABI 0.0:
 *  - In overwrite mode: lowest half of word is used for index.
 *  - In producer-consumer mode: whole word used for index.
 * LTTng crash ABI 1.0:
 *  - Lowest half of word is used for index.
 *  - Limit of 2^16 subbuffers per buffer on 32-bit, 2^32 on 64-bit.
 */
#define SB_ID_INDEX_SHIFT(wl) 0
#define SB_ID_INDEX_COUNT(wl) (1UL << SB_ID_INDEX_SHIFT(wl))
#define SB_ID_INDEX_MASK(wl)  (SB_ID_NOREF_COUNT(wl) - 1)

namespace {
enum class event_record_loss_mode {
	OVERWRITE,
	DISCARD,
};

struct crash_abi_unknown {
	uint8_t magic[RB_CRASH_DUMP_ABI_MAGIC_LEN];
	uint64_t mmap_length; /* Overall length of crash record */
	uint16_t endian; /*
			  * { 0x12, 0x34 }: big endian
			  * { 0x34, 0x12 }: little endian
			  */
	uint16_t major; /* Major number. */
	uint16_t minor; /* Minor number. */
	uint8_t word_size; /* Word size (bytes). */
	uint8_t layout_type; /* enum lttng_crash_layout */
} __attribute__((packed));

struct crash_abi_0_0 {
	struct crash_abi_unknown parent;

	struct {
		uint32_t prod_offset;
		uint32_t consumed_offset;
		uint32_t commit_hot_array;
		uint32_t commit_hot_seq;
		uint32_t buf_wsb_array;
		uint32_t buf_wsb_id;
		uint32_t sb_array;
		uint32_t sb_array_shmp_offset;
		uint32_t sb_backend_p_offset;
		uint32_t content_size;
		uint32_t packet_size;
	} __attribute__((packed)) offset;
	struct {
		uint8_t prod_offset;
		uint8_t consumed_offset;
		uint8_t commit_hot_seq;
		uint8_t buf_wsb_id;
		uint8_t sb_array_shmp_offset;
		uint8_t sb_backend_p_offset;
		uint8_t content_size;
		uint8_t packet_size;
	} __attribute__((packed)) length;
	struct {
		uint32_t commit_hot_array;
		uint32_t buf_wsb_array;
		uint32_t sb_array;
	} __attribute__((packed)) stride;

	uint64_t buf_size; /* Size of the buffer */
	uint64_t subbuf_size; /* Sub-buffer size */
	uint64_t num_subbuf; /* Number of sub-buffers for writer */
	uint32_t mode; /* Buffer mode: 0: overwrite, 1: discard */
} __attribute__((packed));

/*
 * Crash ABI 1.0 always has an extra reader subbuffer.
 */
struct crash_abi_1_0 {
	struct crash_abi_unknown parent;

	struct {
		uint32_t prod_offset;
		uint32_t consumed_offset;
		uint32_t commit_hot_array;
		uint32_t commit_hot_seq;
		uint32_t buf_wsb_array;
		uint32_t buf_wsb_id;
		uint32_t sb_array;
		uint32_t sb_array_shmp_offset;
		uint32_t sb_backend_p_offset;
		uint32_t content_size;
		uint32_t packet_size;
	} __attribute__((packed)) offset;
	struct {
		uint8_t prod_offset;
		uint8_t consumed_offset;
		uint8_t commit_hot_seq;
		uint8_t buf_wsb_id;
		uint8_t sb_array_shmp_offset;
		uint8_t sb_backend_p_offset;
		uint8_t content_size;
		uint8_t packet_size;
	} __attribute__((packed)) length;
	struct {
		uint32_t commit_hot_array;
		uint32_t buf_wsb_array;
		uint32_t sb_array;
	} __attribute__((packed)) stride;

	uint64_t buf_size; /* Size of the buffer */
	uint64_t subbuf_size; /* Sub-buffer size */
	uint64_t num_subbuf; /* Number of sub-buffers for writer */
	uint32_t mode; /* Buffer mode: 0: overwrite, 1: discard */
} __attribute__((packed));

template <typename IntegerType>
std::uint64_t read_int(const void *const location, const bool reverse_byte_order) noexcept
{
	IntegerType value;

	std::memcpy(&value, location, sizeof(value));
	return reverse_byte_order ? lttng::utils::byte_swap(value) : value;
}

template <typename IntegerType>
void write_int(void *const location, const bool reverse_byte_order, const std::uint64_t value)
{
	if (value > std::numeric_limits<IntegerType>::max()) {
		LTTNG_THROW_OUT_OF_RANGE(
			fmt::format("Value doesn't fit in field: value={}, field_length_bytes={}",
				    value,
				    sizeof(IntegerType)));
	}

	const auto narrowed = static_cast<IntegerType>(value);
	const auto encoded = reverse_byte_order ? lttng::utils::byte_swap(narrowed) : narrowed;

	std::memcpy(location, &encoded, sizeof(encoded));
}

bool has_extra_reader_subbuf(const crash_abi_0_0&, const event_record_loss_mode mode) noexcept
{
	return mode == event_record_loss_mode::OVERWRITE;
}

bool has_extra_reader_subbuf(const crash_abi_1_0&, const event_record_loss_mode) noexcept
{
	return true;
}

enum class field_length : unsigned int {
	ONE_BYTE = 1,
	TWO_BYTES = 2,
	FOUR_BYTES = 4,
	EIGHT_BYTES = 8,
};

enum class word_length : unsigned int {
	FOUR_BYTES = 4,
	EIGHT_BYTES = 8,
};

class field_descriptor final {
public:
	explicit field_descriptor(lttng::c_string_view name,
				  const std::uint64_t offset_from_structure_start,
				  const std::uint64_t byte_count) :
		_name(name),
		_offset_from_structure_start(offset_from_structure_start),
		_length(_length_from_byte_count(name, byte_count))
	{
	}

	field_descriptor(const field_descriptor&) = default;
	field_descriptor(field_descriptor&&) = default;
	field_descriptor& operator=(const field_descriptor&) = delete;
	field_descriptor& operator=(field_descriptor&&) = delete;
	~field_descriptor() = default;

	lttng::c_string_view name() const noexcept
	{
		return _name;
	}

	std::uint64_t offset_from_structure_start() const noexcept
	{
		return _offset_from_structure_start;
	}

	field_length length() const noexcept
	{
		return _length;
	}

private:
	static field_length _length_from_byte_count(const lttng::c_string_view name,
						    const std::uint64_t byte_count)
	{
		switch (byte_count) {
		case 1:
			return field_length::ONE_BYTE;
		case 2:
			return field_length::TWO_BYTES;
		case 4:
			return field_length::FOUR_BYTES;
		case 8:
			return field_length::EIGHT_BYTES;
		default:
			LTTNG_THROW_INVALID_ARGUMENT_ERROR(fmt::format(
				"Unsupported length of crash ABI header field `{}`: length={}",
				name,
				byte_count));
		}
	}

	lttng::c_string_view _name;
	const std::uint64_t _offset_from_structure_start;
	const field_length _length;
};

class array_descriptor final {
public:
	explicit array_descriptor(lttng::c_string_view name,
				  const std::uint64_t offset_from_file_start,
				  const std::uint64_t stride) noexcept :
		_name(name), _offset_from_file_start(offset_from_file_start), _stride(stride)
	{
	}

	array_descriptor(const array_descriptor&) = default;
	array_descriptor(array_descriptor&&) = default;
	array_descriptor& operator=(const array_descriptor&) = delete;
	array_descriptor& operator=(array_descriptor&&) = delete;
	~array_descriptor() = default;

	lttng::c_string_view name() const noexcept
	{
		return _name;
	}

	std::uint64_t offset_from_file_start() const noexcept
	{
		return _offset_from_file_start;
	}

	std::uint64_t stride() const noexcept
	{
		return _stride;
	}

private:
	lttng::c_string_view _name;
	const std::uint64_t _offset_from_file_start;
	const std::uint64_t _stride;
};

class header_reader final {
public:
	explicit header_reader(bool reverse_byte_order) noexcept :
		_reverse_byte_order(reverse_byte_order)
	{
	}

	bool reverse_byte_order() const noexcept
	{
		return _reverse_byte_order;
	}

	template <typename IntegerType>
	std::uint64_t value(IntegerType raw_value) const noexcept
	{
		return read_int<IntegerType>(&raw_value, _reverse_byte_order);
	}

	template <typename OffsetType, typename LengthType>
	field_descriptor
	field(const lttng::c_string_view name, OffsetType raw_offset, LengthType raw_length) const
	{
		return field_descriptor(name, value(raw_offset), value(raw_length));
	}

	template <typename OffsetType, typename LengthType>
	std::optional<field_descriptor> optional_field(const lttng::c_string_view name,
						       OffsetType raw_offset,
						       LengthType raw_length) const
	{
		/* lttng-ust sets a length of zero when the field isn't populated. */
		if (value(raw_length) == 0) {
			return std::nullopt;
		}

		return field(name, raw_offset, raw_length);
	}

	template <typename OffsetType, typename StrideType>
	array_descriptor
	array(const lttng::c_string_view name, OffsetType raw_offset, StrideType raw_stride) const
	{
		return array_descriptor(name, value(raw_offset), value(raw_stride));
	}

private:
	const bool _reverse_byte_order;
};

struct crash_field_layout {
	template <typename AbiType>
	crash_field_layout(const AbiType& abi, const header_reader& reader) :
		field{ reader.field("prod_offset", abi.offset.prod_offset, abi.length.prod_offset),
		       reader.field("consumed_offset",
				    abi.offset.consumed_offset,
				    abi.length.consumed_offset),
		       reader.field("commit_hot_seq",
				    abi.offset.commit_hot_seq,
				    abi.length.commit_hot_seq),
		       reader.field("buf_wsb_id", abi.offset.buf_wsb_id, abi.length.buf_wsb_id),
		       reader.field("sb_array_shmp_offset",
				    abi.offset.sb_array_shmp_offset,
				    abi.length.sb_array_shmp_offset),
		       reader.field("sb_backend_p_offset",
				    abi.offset.sb_backend_p_offset,
				    abi.length.sb_backend_p_offset),
		       reader.optional_field(
			       "content_size", abi.offset.content_size, abi.length.content_size),
		       reader.optional_field(
			       "packet_size", abi.offset.packet_size, abi.length.packet_size) },
		array{ reader.array("commit_hot_array",
				    abi.offset.commit_hot_array,
				    abi.stride.commit_hot_array),
		       reader.array(
			       "buf_wsb_array", abi.offset.buf_wsb_array, abi.stride.buf_wsb_array),
		       reader.array("sb_array", abi.offset.sb_array, abi.stride.sb_array) },
		reverse_byte_order(reader.reverse_byte_order())
	{
	}

	crash_field_layout(const crash_field_layout&) = default;
	crash_field_layout(crash_field_layout&&) = default;
	crash_field_layout& operator=(const crash_field_layout&) = delete;
	crash_field_layout& operator=(crash_field_layout&&) = delete;
	~crash_field_layout() = default;

	struct {
		const field_descriptor prod_offset;
		const field_descriptor consumed_offset;
		const field_descriptor commit_hot_seq;
		const field_descriptor buf_wsb_id;
		const field_descriptor sb_array_shmp_offset;
		const field_descriptor sb_backend_p_offset;
		const std::optional<field_descriptor> content_size;
		const std::optional<field_descriptor> packet_size;
	} field;
	struct {
		const array_descriptor commit_hot;
		const array_descriptor buf_wsb;
		const array_descriptor sb;
	} array;

	const bool reverse_byte_order;
};

struct ring_buffer_properties {
	template <typename AbiType>
	ring_buffer_properties(const AbiType& abi, const header_reader& reader) :
		word_size(_word_size_from_value(reader.value(abi.parent.word_size))),
		buf_size(reader.value(abi.buf_size)),
		subbuf_size(reader.value(abi.subbuf_size)),
		num_subbuf(reader.value(abi.num_subbuf)),
		mode(_mode_from_value(reader.value(abi.mode))),
		extra_reader_subbuf(has_extra_reader_subbuf(abi, mode))
	{
		_validate();
	}

	ring_buffer_properties(const ring_buffer_properties&) = default;
	ring_buffer_properties(ring_buffer_properties&&) = default;
	ring_buffer_properties& operator=(const ring_buffer_properties&) = delete;
	ring_buffer_properties& operator=(ring_buffer_properties&&) = delete;
	~ring_buffer_properties() = default;

	const word_length word_size;
	const std::uint64_t buf_size;
	const std::uint64_t subbuf_size;
	const std::uint64_t num_subbuf;
	const event_record_loss_mode mode;
	const bool extra_reader_subbuf;

private:
	static word_length _word_size_from_value(const std::uint64_t value)
	{
		switch (value) {
		case 4:
			return word_length::FOUR_BYTES;
		case 8:
			return word_length::EIGHT_BYTES;
		default:
			LTTNG_THROW_INVALID_ARGUMENT_ERROR(fmt::format(
				"Unsupported word size in crash ABI header: {}", value));
		}
	}

	static event_record_loss_mode _mode_from_value(const std::uint64_t value)
	{
		switch (value) {
		case 0:
			return event_record_loss_mode::OVERWRITE;
		case 1:
			return event_record_loss_mode::DISCARD;
		default:
			LTTNG_THROW_INVALID_ARGUMENT_ERROR(fmt::format(
				"Unsupported ring buffer mode in crash ABI header: {}", value));
		}
	}

	void _validate() const
	{
		if (!lttng::math::is_power_of_two(subbuf_size) ||
		    !lttng::math::is_power_of_two(num_subbuf) ||
		    subbuf_size > UINT64_MAX / num_subbuf || buf_size != subbuf_size * num_subbuf) {
			LTTNG_THROW_INVALID_ARGUMENT_ERROR(fmt::format(
				"Invalid ring buffer geometry: buf_size={}, subbuf_size={}, num_subbuf={}",
				buf_size,
				subbuf_size,
				num_subbuf));
		}
	}
};

struct crash_header {
	template <typename AbiType>
	crash_header(const AbiType& abi, const header_reader& reader) :
		layout(abi, reader),
		properties(abi, reader),
		mmap_length(reader.value(abi.parent.mmap_length))
	{
		_validate();
	}

	crash_header(const crash_header&) = default;
	crash_header(crash_header&&) = default;
	crash_header& operator=(const crash_header&) = delete;
	crash_header& operator=(crash_header&&) = delete;
	~crash_header() = default;

	const crash_field_layout layout;
	const ring_buffer_properties properties;

	/* Length of the ring buffer, header included. */
	const std::uint64_t mmap_length;

private:
	void _validate() const
	{
		for (const auto *const array :
		     { &layout.array.commit_hot, &layout.array.buf_wsb, &layout.array.sb }) {
			if (array->stride() == 0) {
				LTTNG_THROW_INVALID_ARGUMENT_ERROR(fmt::format(
					"Invalid zero stride of crash ABI header array `{}`: offset_from_file_start={:#x}",
					array->name(),
					array->offset_from_file_start()));
			}
		}

		if (properties.buf_size > mmap_length) {
			LTTNG_THROW_INVALID_ARGUMENT_ERROR(fmt::format(
				"Ring buffer is larger than the buffer file: buf_size={}, mmap_length={}",
				properties.buf_size,
				mmap_length));
		}
	}
};
} /* namespace */

namespace fmt {
template <>
struct formatter<field_descriptor> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(const field_descriptor& field,
						    FormatContextType& ctx) const
	{
		return format_to(ctx.out(),
				 "{{offset_from_structure_start={:#x}, length={}}}",
				 field.offset_from_structure_start(),
				 static_cast<unsigned int>(field.length()));
	}
};

template <>
struct formatter<array_descriptor> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(const array_descriptor& array,
						    FormatContextType& ctx) const
	{
		return format_to(ctx.out(),
				 "{{offset_from_file_start={:#x}, stride={}}}",
				 array.offset_from_file_start(),
				 array.stride());
	}
};

template <>
struct formatter<event_record_loss_mode> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(const event_record_loss_mode mode,
						    FormatContextType& ctx) const
	{
		return format_to(ctx.out(),
				 "{}",
				 mode == event_record_loss_mode::OVERWRITE ? "overwrite" :
									     "discard");
	}
};
} /* namespace fmt */

/* Variables */
namespace {
const char *progname;
char *opt_viewer_path = nullptr;
char *opt_output_path = nullptr;

char *the_input_path;
} /* namespace */

int lttng_opt_quiet, lttng_opt_verbose, lttng_opt_mi;
bool lttng_opt_is_tui = true;

enum {
	OPT_DUMP_OPTIONS,
};

namespace {
/* Getopt options. No first level command. */
struct option long_options[] = {
	{ "version", 0, nullptr, 'V' }, { "help", 0, nullptr, 'h' },
	{ "verbose", 0, nullptr, 'v' }, { "viewer", 1, nullptr, 'e' },
	{ "extract", 1, nullptr, 'x' }, { "list-options", 0, nullptr, OPT_DUMP_OPTIONS },
	{ nullptr, 0, nullptr, 0 },
};

void usage()
{
	const int ret = utils_show_help(1, "lttng-crash", help_msg);

	if (ret) {
		ERR("Cannot show --help for `lttng-crash`");
		perror("exec");
	}
}

void version(FILE *ofp)
{
	const char *const git_version = lttng::get_git_version();

	fprintf(ofp,
		"%s (LTTng Crash Trace Viewer) " VERSION " - " VERSION_NAME "%s%s%s\n",
		progname,
		git_version[0] == '\0' ? "" : " - ",
		git_version,
		EXTRA_VERSION_NAME[0] == '\0' ? "" : " - " EXTRA_VERSION_NAME);
}

/*
 *  list_options
 *
 *  List options line by line. This is mostly for bash auto completion and to
 *  avoid difficult parsing.
 */
void list_options(FILE *ofp)
{
	int i = 0;
	struct option *option = nullptr;

	option = &long_options[i];
	while (option->name != nullptr) {
		fprintf(ofp, "--%s\n", option->name);

		if (isprint(option->val)) {
			fprintf(ofp, "-%c\n", option->val);
		}

		i++;
		option = &long_options[i];
	}
}

/*
 * Parse command line arguments.
 *
 * Return 0 if OK, else -1
 */
int parse_args(int argc, char **argv)
{
	int opt, ret = 0;

	if (argc < 2) {
		usage();
		return -1;
	}

	while ((opt = getopt_long(argc, argv, "+Vhve:x:", long_options, nullptr)) != -1) {
		switch (opt) {
		case 'V':
			version(stdout);
			ret = 1;
			goto end;
		case 'h':
			usage();
			ret = 1;
			goto end;
		case 'v':
			/* There is only 3 possible level of verbosity. (-vvv) */
			if (lttng_opt_verbose < 3) {
				lttng_opt_verbose += 1;
			}
			break;
		case 'e':
			free(opt_viewer_path);
			opt_viewer_path = strdup(optarg);
			break;
		case 'x':
			free(opt_output_path);
			opt_output_path = strdup(optarg);
			break;
		case OPT_DUMP_OPTIONS:
			list_options(stdout);
			ret = 1;
			goto end;
		default:
			ERR("Unknown command-line option");
			goto error;
		}
	}

	/* No leftovers, or more than one input path, print usage and quit */
	if (argc - optind != 1) {
		ERR("Command-line error: Specify exactly one input path");
		goto error;
	}

	the_input_path = argv[optind];
end:
	return ret;

error:
	return -1;
}

template <typename... FormattingArgumentTypes>
void log_error_with_causes(const std::exception& exception,
			   lttng::c_string_view summary_format,
			   FormattingArgumentTypes&&...arguments) noexcept
{
	try {
		auto message = fmt::format(summary_format.data(),
					   std::forward<FormattingArgumentTypes>(arguments)...);
		std::string innermost_location;

		lttng::visit_nested_exceptions(
			exception,
			[&message, &innermost_location](const std::exception& cause,
							const unsigned int) {
				message += fmt::format("\n  Caused by: {}", cause.what());

				const auto *const lttng_cause =
					dynamic_cast<const lttng::runtime_error *>(&cause);

				innermost_location = lttng_cause ?
					fmt::format(
						" (in {}() at {}:{})",
						lttng_cause->source_location.function_name.data(),
						lttng_cause->source_location.file_name.data(),
						lttng_cause->source_location.line_number) :
					std::string();
			});

		if (lttng_opt_verbose > 0) {
			/* Omit source location in non-verbose output. */
			message += innermost_location;
		}

		ERR("%s", message.c_str());
	} catch (const std::exception& formatting_exception) {
		ERR("Failed to format error: %s: original_error=`%s`",
		    formatting_exception.what(),
		    exception.what());
	}
}

void copy_file_range(const lttng::output_stream_descriptor& destination_fd,
		     const lttng::input_stream_descriptor& source_fd,
		     const std::uint64_t offset_from_file_start,
		     const std::uint64_t length)
{
	auto read_offset_from_file_start = static_cast<off_t>(offset_from_file_start);
	auto remaining = length;

	while (remaining > 0) {
		/* `remaining` may not fit in a `size_t` on 32-bit platforms. */
		const auto chunk_length = static_cast<std::size_t>(
			std::min<std::uint64_t>(remaining, std::numeric_limits<ssize_t>::max()));
		const auto ret = sendfile(destination_fd.fd(),
					  source_fd.fd(),
					  &read_offset_from_file_start,
					  chunk_length);

		if (ret < 0 && errno == EINTR) {
			continue;
		} else if (ret < 0) {
			LTTNG_THROW_POSIX(
				fmt::format("Failed to copy a file range: offset={:#x}, length={}",
					    offset_from_file_start,
					    length));
		} else if (ret == 0) {
			LTTNG_THROW_ERROR(fmt::format(
				"Unexpected end of file while copying a file range: offset={:#x}, length={}, copied_length={}",
				offset_from_file_start,
				length,
				length - remaining));
		}

		remaining -= ret;
	}
}

void copy_file(const std::string& destination_path, const std::string& source_path)
{
	DBG_FMT("Copying metadata file: source_path=`{}`, destination_path=`{}`",
		source_path,
		destination_path);

	const auto raw_source_fd = open(source_path.c_str(), O_RDONLY);
	if (raw_source_fd < 0) {
		LTTNG_THROW_POSIX(fmt::format("Failed to open `{}` for reading", source_path));
	}

	const lttng::input_stream_descriptor source_fd(raw_source_fd);

	const auto raw_destination_fd = open(destination_path.c_str(),
					     O_RDWR | O_CREAT | O_EXCL,
					     S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (raw_destination_fd < 0) {
		LTTNG_THROW_POSIX(fmt::format("Failed to open `{}` for writing", destination_path));
	}

	const lttng::output_stream_descriptor destination_fd(raw_destination_fd);

	lttng::scope_exit remove_destination_file([&destination_path]() noexcept {
		if (unlink(destination_path.c_str())) {
			PERROR("Failed to remove '%s'", destination_path.c_str());
		}
	});

	struct stat source_stat;
	if (fstat(source_fd.fd(), &source_stat)) {
		LTTNG_THROW_POSIX(fmt::format("Failed to get the size of `{}`", source_path));
	}

	copy_file_range(
		destination_fd, source_fd, 0, static_cast<std::uint64_t>(source_stat.st_size));
	remove_destination_file.disarm();
}

std::uint64_t
read_int(const void *const location, const field_length length, const bool reverse_byte_order)
{
	switch (length) {
	case field_length::ONE_BYTE:
		return read_int<std::uint8_t>(location, reverse_byte_order);
	case field_length::TWO_BYTES:
		return read_int<std::uint16_t>(location, reverse_byte_order);
	case field_length::FOUR_BYTES:
		return read_int<std::uint32_t>(location, reverse_byte_order);
	case field_length::EIGHT_BYTES:
		return read_int<std::uint64_t>(location, reverse_byte_order);
	}

	/* Unreachable: `field_descriptor` only holds supported lengths. */
	abort();
}

void write_int(void *const location,
	       const field_length length,
	       const bool reverse_byte_order,
	       const std::uint64_t value)
{
	switch (length) {
	case field_length::ONE_BYTE:
		return write_int<std::uint8_t>(location, reverse_byte_order, value);
	case field_length::TWO_BYTES:
		return write_int<std::uint16_t>(location, reverse_byte_order, value);
	case field_length::FOUR_BYTES:
		return write_int<std::uint32_t>(location, reverse_byte_order, value);
	case field_length::EIGHT_BYTES:
		return write_int<std::uint64_t>(location, reverse_byte_order, value);
	}

	abort();
}

void print_dbg_magic(const uint8_t *magic)
{
	DBG("magic: 0x%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X",
	    magic[0],
	    magic[1],
	    magic[2],
	    magic[3],
	    magic[4],
	    magic[5],
	    magic[6],
	    magic[7],
	    magic[8],
	    magic[9],
	    magic[10],
	    magic[11],
	    magic[12],
	    magic[13],
	    magic[14],
	    magic[15]);
}

bool is_valid_magic(const uint8_t *magic) noexcept
{
	for (int i = 0; i < RB_CRASH_DUMP_ABI_MAGIC_LEN; i++) {
		if ((magic[i] ^ 0xFF) != lttng_crash_expected_magic_xor[i]) {
			return false;
		}
	}

	return true;
}

std::uint64_t max_word_value(const ring_buffer_properties& properties) noexcept
{
	return properties.word_size == word_length::FOUR_BYTES ? UINT32_MAX : UINT64_MAX;
}

/*
 * With a 32-bit ABI, the free-running counters are expected to overflow, so
 * compare them at the word size of the ABI rather than as 64-bit values.
 */
bool counter_is_before(const ring_buffer_properties& properties,
		       std::uint64_t counter,
		       std::uint64_t other_counter) noexcept
{
	const auto mask = max_word_value(properties);

	/* Tests the sign bit of the difference, like the ring buffer does with `long`. */
	return ((counter - other_counter) & mask) > mask / 2;
}

std::optional<crash_header> decode_crash_header(lttng::input_stream_descriptor& fd)
{
	constexpr auto max_header_length = sizeof(crash_abi_1_0);
	std::array<char, max_header_length> header_bytes{};
	const auto header_length = fd.read_some(header_bytes.data(), header_bytes.size());
	const auto abi =
		lttng::binary_view<crash_abi_unknown>(header_bytes.data(), header_length).value();

	print_dbg_magic(abi.magic);
	if (!is_valid_magic(abi.magic)) {
		DBG("Unknown magic number");
		return std::nullopt;
	}

	bool reverse_byte_order = false;
	const auto endian = header_reader(false).value(abi.endian);
	switch (endian) {
	case RB_CRASH_ENDIAN:
		break;
	case RB_CRASH_ENDIAN_REVERSE:
		reverse_byte_order = true;
		break;
	default:
		DBG("Unknown endianness value: 0x%X", (unsigned int) endian);
		return std::nullopt;
	}

	const header_reader reader(reverse_byte_order);
	const auto layout_type = (enum lttng_crash_type) reader.value(abi.layout_type);
	switch (layout_type) {
	case LTTNG_CRASH_TYPE_UST:
		break;
	case LTTNG_CRASH_TYPE_KERNEL:
		ERR("lttng-modules buffer layout support not implemented");
		return std::nullopt;
	default:
		ERR("Unknown layout type %u", (unsigned int) layout_type);
		return std::nullopt;
	}

	DBG("mmap_length: %" PRIu64, reader.value(abi.mmap_length));
	const auto major = reader.value(abi.major);
	DBG("major: %" PRIu64, major);
	const auto minor = reader.value(abi.minor);
	DBG("minor: %" PRIu64, minor);
	DBG("word_size: %" PRIu64, reader.value(abi.word_size));

	std::optional<crash_header> header;

	if (major == 0 && minor == 0) {
		header.emplace(lttng::binary_view<crash_abi_0_0>(header_bytes.data(), header_length)
				       .value(),
			       reader);
	} else if (major == 1 && minor == 0) {
		header.emplace(lttng::binary_view<crash_abi_1_0>(header_bytes.data(), header_length)
				       .value(),
			       reader);
	} else {
		LTTNG_THROW_UNSUPPORTED_ERROR(
			fmt::format("Unsupported crash ABI {}.{}", major, minor));
	}

	DBG_FMT("Crash ABI fields: prod_offset={}, consumed_offset={}, commit_hot_seq={}, "
		"buf_wsb_id={}, sb_array_shmp_offset={}, sb_backend_p_offset={}, "
		"content_size={}, packet_size={}",
		header->layout.field.prod_offset,
		header->layout.field.consumed_offset,
		header->layout.field.commit_hot_seq,
		header->layout.field.buf_wsb_id,
		header->layout.field.sb_array_shmp_offset,
		header->layout.field.sb_backend_p_offset,
		header->layout.field.content_size,
		header->layout.field.packet_size);
	DBG_FMT("Crash ABI arrays: commit_hot={}, buf_wsb={}, sb={}",
		header->layout.array.commit_hot,
		header->layout.array.buf_wsb,
		header->layout.array.sb);
	DBG_FMT("Ring buffer properties: word_size={}, buf_size={}, subbuf_size={}, num_subbuf={}, "
		"mode={}, extra_reader_subbuf={}",
		static_cast<unsigned int>(header->properties.word_size),
		header->properties.buf_size,
		header->properties.subbuf_size,
		header->properties.num_subbuf,
		header->properties.mode,
		header->properties.extra_reader_subbuf);
	return header;
}

struct file_range {
	file_range(const file_range&) = default;
	file_range(file_range&&) = default;
	file_range& operator=(const file_range&) = delete;
	file_range& operator=(file_range&&) = delete;
	~file_range() = default;

	const std::uint64_t offset_from_file_start;
	const std::uint64_t length;
};

class crash_buffer final {
public:
	explicit crash_buffer(lttng::input_stream_descriptor fd,
			      crash_field_layout layout,
			      const std::uint64_t mmap_length) :
		_fd(std::move(fd)), _layout(std::move(layout)), _mmap_length(mmap_length)
	{
		struct stat file_stat;

		if (fstat(_fd.fd(), &file_stat) < 0) {
			LTTNG_THROW_POSIX("Failed to stat the buffer file");
		}

		if (_mmap_length > static_cast<std::uint64_t>(file_stat.st_size)) {
			LTTNG_THROW_INVALID_ARGUMENT_ERROR(fmt::format(
				"Buffer file is shorter than its declared length: mmap_length={}, file_size={}",
				_mmap_length,
				file_stat.st_size));
		}
	}

	crash_buffer(const crash_buffer&) = delete;
	crash_buffer(crash_buffer&&) = delete;
	crash_buffer& operator=(const crash_buffer&) = delete;
	crash_buffer& operator=(crash_buffer&&) = delete;
	~crash_buffer() = default;

	const crash_field_layout& layout() const noexcept
	{
		return _layout;
	}

	std::uint64_t read(const field_descriptor& field,
			   const std::uint64_t structure_offset_from_file_start) const
	{
		std::array<char, sizeof(std::uint64_t)> bytes;

		_fd.read_at(
			bytes.data(),
			static_cast<std::size_t>(field.length()),
			static_cast<off_t>(_field_offset(field, structure_offset_from_file_start)));

		return read_int(bytes.data(), field.length(), _layout.reverse_byte_order);
	}

	std::uint64_t read(const array_descriptor& array,
			   const std::uint64_t index,
			   const field_descriptor& field) const
	{
		try {
			return read(field, _element_offset(array, index));
		} catch (...) {
			std::throw_with_nested(
				lttng::runtime_error(fmt::format("Failed to read `{}[{}].{}`",
								 array.name(),
								 index,
								 field.name()),
						     LTTNG_SOURCE_LOCATION()));
		}
	}

	file_range range(const std::uint64_t offset_from_file_start,
			 const std::uint64_t length) const
	{
		if (!_is_within_file(offset_from_file_start, length)) {
			LTTNG_THROW_OUT_OF_RANGE(fmt::format(
				"File range is past the end of the buffer file: offset_from_file_start={:#x}, length={}, mmap_length={}",
				offset_from_file_start,
				length,
				_mmap_length));
		}

		return { offset_from_file_start, length };
	}

	void copy(const file_range& source,
		  std::uint64_t length,
		  const lttng::output_stream_descriptor& fd_dest) const
	{
		if (length > source.length) {
			LTTNG_THROW_OUT_OF_RANGE(fmt::format(
				"Copy is larger than its source range: length={}, range_length={}",
				length,
				source.length));
		}

		copy_file_range(fd_dest, _fd, source.offset_from_file_start, length);
	}

private:
	bool _is_within_file(const std::uint64_t offset_from_file_start,
			     const std::uint64_t length) const noexcept
	{
		return length <= _mmap_length && offset_from_file_start <= _mmap_length - length;
	}

	std::uint64_t _field_offset(const field_descriptor& field,
				    const std::uint64_t structure_offset_from_file_start) const
	{
		const auto length = static_cast<std::uint64_t>(field.length());

		/* Checks the terms first so that their sum doesn't overflow. */
		if (structure_offset_from_file_start > _mmap_length ||
		    field.offset_from_structure_start() >
			    _mmap_length - structure_offset_from_file_start ||
		    !_is_within_file(structure_offset_from_file_start +
					     field.offset_from_structure_start(),
				     length)) {
			LTTNG_THROW_OUT_OF_RANGE(fmt::format(
				"Field `{}` is past the end of the buffer file: structure_offset_from_file_start={:#x}, field_offset_from_structure_start={:#x}, field_length={}, mmap_length={}",
				field.name(),
				structure_offset_from_file_start,
				field.offset_from_structure_start(),
				length,
				_mmap_length));
		}

		return structure_offset_from_file_start + field.offset_from_structure_start();
	}

	std::uint64_t _element_offset(const array_descriptor& array,
				      const std::uint64_t index) const
	{
		if (array.offset_from_file_start() > _mmap_length ||
		    (array.stride() != 0 &&
		     index > (_mmap_length - array.offset_from_file_start()) / array.stride())) {
			LTTNG_THROW_OUT_OF_RANGE(fmt::format(
				"Element of array `{}` is past the end of the buffer file: index={}, array_offset_from_file_start={:#x}, stride={}, mmap_length={}",
				array.name(),
				index,
				array.offset_from_file_start(),
				array.stride(),
				_mmap_length));
		}

		return array.offset_from_file_start() + (index * array.stride());
	}

	lttng::input_stream_descriptor _fd;
	const crash_field_layout _layout;
	const std::uint64_t _mmap_length;
};

void patch_packet_field(const lttng::output_stream_descriptor& fd_dest,
			off_t packet_offset_from_file_start,
			std::uint64_t packet_size,
			const field_descriptor& field,
			bool reverse_byte_order,
			std::uint64_t value)
{
	const auto length = static_cast<std::uint64_t>(field.length());

	if (length > packet_size || field.offset_from_structure_start() > packet_size - length) {
		LTTNG_THROW_OUT_OF_RANGE(fmt::format(
			"Packet header field `{}` is outside of the packet: field_offset_from_packet_start={:#x}, field_length={}, packet_size={}",
			field.name(),
			field.offset_from_structure_start(),
			length,
			packet_size));
	}

	try {
		std::array<char, sizeof(std::uint64_t)> bytes;

		write_int(bytes.data(), field.length(), reverse_byte_order, value);
		fd_dest.write_at(bytes.data(),
				 static_cast<std::size_t>(length),
				 packet_offset_from_file_start +
					 static_cast<off_t>(field.offset_from_structure_start()));
	} catch (...) {
		std::throw_with_nested(lttng::runtime_error(
			fmt::format("Failed to patch packet header field `{}` in the output file",
				    field.name()),
			LTTNG_SOURCE_LOCATION()));
	}
}

/* buf_trunc mask selects only the buffer number. */
inline uint64_t buf_trunc(uint64_t offset, uint64_t buf_size)
{
	return offset & ~(buf_size - 1);
}

/* subbuf_trunc mask selects the subbuffer number. */
inline uint64_t subbuf_trunc(uint64_t offset, uint64_t subbuf_size)
{
	return offset & ~(subbuf_size - 1);
}

/* buf_offset mask selects only the offset within the current buffer. */
inline uint64_t buf_offset(uint64_t offset, uint64_t buf_size)
{
	return offset & (buf_size - 1);
}

/* subbuf_offset mask selects the offset within the current subbuffer. */
inline uint64_t subbuf_offset(uint64_t offset, uint64_t subbuf_size)
{
	return offset & (subbuf_size - 1);
}

/* subbuf_index returns the index of the current subbuffer within the buffer. */
inline uint64_t subbuf_index(uint64_t offset, uint64_t buf_size, uint64_t subbuf_size)
{
	return buf_offset(offset, buf_size) / subbuf_size;
}

inline uint64_t subbuffer_id_get_index(bool extra_reader_subbuf, uint64_t id, unsigned int wl)
{
	if (extra_reader_subbuf)
		return id & SB_ID_INDEX_MASK(wl);
	else
		return id;
}

/* `produced_counter_at_subbuf_start` is `consumed` in lttng-ust's lib_ring_buffer_get_subbuf(). */
bool copy_crash_subbuf(const crash_buffer& buffer,
		       const ring_buffer_properties& properties,
		       const lttng::output_stream_descriptor& fd_dest,
		       uint64_t produced_counter_at_subbuf_start)
{
	const auto& layout = buffer.layout();
	const auto buf_size = properties.buf_size;
	const auto subbuf_size = properties.subbuf_size;
	const auto num_subbuf = properties.num_subbuf;
	const auto commit_count_mask = max_word_value(properties) / num_subbuf;

	DBG("Copy crash sub-buffer: produced_counter_at_subbuf_start=0x%" PRIx64,
	    produced_counter_at_subbuf_start);

	/* lttng-ust: `idx` (from subbuf_index()). */
	const auto writer_subbuf_index =
		subbuf_index(produced_counter_at_subbuf_start, buf_size, subbuf_size);
	/* lttng-ust: `commit_hot[idx].seq`. */
	const auto commit_seq = buffer.read(
		layout.array.commit_hot, writer_subbuf_index, layout.field.commit_hot_seq);
	/* lttng-ust: `buf->consumed`. */
	const auto consumed_counter = buffer.read(layout.field.consumed_offset, 0);

	if (counter_is_before(properties,
			      subbuf_trunc(produced_counter_at_subbuf_start, subbuf_size),
			      subbuf_trunc(consumed_counter, subbuf_size))) {
		DBG("No data: sub-buffer starts before the consumed counter");
		return false;
	}

	uint64_t committed_size;

	if (((commit_seq - subbuf_size) & commit_count_mask) -
		    (buf_trunc(produced_counter_at_subbuf_start, buf_size) / num_subbuf) ==
	    0) {
		committed_size = subbuf_size;
	} else {
		committed_size = subbuf_offset(commit_seq, subbuf_size);
		if (!committed_size) {
			DBG("No data committed: commit_seq=%" PRIu64, commit_seq);
			return false;
		}
	}

	/*
	 * To read a sub-buffer, the reader exchanges it with the spare sub-buffer of the ring
	 * buffer, so writer sub-buffer N isn't always backend sub-buffer N. The index part of
	 * `buf_wsb[N].id` gives the actual backend sub-buffer, of which the backend pages
	 * structure gives the location of the data.
	 */
	/* lttng-ust: `wsb->id`. */
	const auto subbuf_id =
		buffer.read(layout.array.buf_wsb, writer_subbuf_index, layout.field.buf_wsb_id);
	/* lttng-ust: `sb_bindex`. */
	const auto backend_subbuf_index =
		subbuffer_id_get_index(properties.extra_reader_subbuf,
				       subbuf_id,
				       static_cast<unsigned int>(properties.word_size));
	/* lttng-ust: `rpages`. */
	const auto backend_pages_offset_from_file_start = buffer.read(
		layout.array.sb, backend_subbuf_index, layout.field.sb_array_shmp_offset);
	/* Name the backend sub-buffer since `sb_array` gives the offset of its pages. */
	const auto subbuf = [&]() -> file_range {
		try {
			/* lttng-ust: `rpages->p`. */
			return buffer.range(buffer.read(layout.field.sb_backend_p_offset,
							backend_pages_offset_from_file_start),
					    subbuf_size);
		} catch (...) {
			std::throw_with_nested(lttng::runtime_error(
				fmt::format(
					"Failed to locate the data of backend sub-buffer {}: backend_pages_offset_from_file_start={:#x}",
					backend_subbuf_index,
					backend_pages_offset_from_file_start),
				LTTNG_SOURCE_LOCATION()));
		}
	}();
	uint64_t packet_size;

	if (committed_size == subbuf_size) {
		if (layout.field.packet_size) {
			packet_size = buffer.read(*layout.field.packet_size,
						  subbuf.offset_from_file_start) /
				CHAR_BIT;
			if (packet_size > subbuf_size) {
				LTTNG_THROW_INVALID_ARGUMENT_ERROR(fmt::format(
					"Packet is larger than its sub-buffer: packet_size={}, subbuf_size={}",
					packet_size,
					subbuf_size));
			}
		} else {
			packet_size = subbuf_size;
		}
	} else {
		packet_size = committed_size;
	}

	const auto packet_offset_from_file_start = lseek(fd_dest.fd(), 0, SEEK_CUR);
	if (packet_offset_from_file_start < 0) {
		LTTNG_THROW_POSIX("Failed to get the position of the output file");
	}

	buffer.copy(subbuf, packet_size, fd_dest);

	if (committed_size != subbuf_size) {
		/*
		 * The tracer writes the packet header sizes only when it closes the packet;
		 * otherwise, we have to patch them with the committed size in the output file.
		 */
		const uint64_t committed_size_bits = committed_size * CHAR_BIT;

		if (layout.field.content_size) {
			patch_packet_field(fd_dest,
					   packet_offset_from_file_start,
					   packet_size,
					   *layout.field.content_size,
					   layout.reverse_byte_order,
					   committed_size_bits);
		}

		if (layout.field.packet_size) {
			patch_packet_field(fd_dest,
					   packet_offset_from_file_start,
					   packet_size,
					   *layout.field.packet_size,
					   layout.reverse_byte_order,
					   committed_size_bits);
		}
	}

	DBG("Copied %" PRIu64 " bytes of data", packet_size);
	return true;
}

bool copy_crash_data(const crash_buffer& buffer,
		     const ring_buffer_properties& properties,
		     const lttng::output_stream_descriptor& fd_dest)
{
	const auto& layout = buffer.layout();
	/* lttng-ust: `buf->offset`. */
	const auto produced_counter = buffer.read(layout.field.prod_offset, 0);
	DBG("produced_counter: 0x%" PRIx64, produced_counter);
	/* lttng-ust: `buf->consumed`. */
	auto consumed_counter = buffer.read(layout.field.consumed_offset, 0);
	DBG("consumed_counter: 0x%" PRIx64, consumed_counter);

	/*
	 * With a 32-bit ABI, the free-running counters are expected to overflow,
	 * which makes their difference huge once read as 64-bit values. Bring it back
	 * within the 32-bit range when that happens.
	 */
	auto produced_size = (produced_counter - consumed_counter) & max_word_value(properties);

	if (produced_size > properties.buf_size &&
	    properties.mode == event_record_loss_mode::OVERWRITE) {
		/*
		 * A writer pushes the consumed counter after moving the produced counter, so
		 * the application may have crashed in between. Push it like the tracer would.
		 */
		consumed_counter = (subbuf_trunc(produced_counter - 1, properties.subbuf_size) -
				    properties.buf_size + properties.subbuf_size) &
			max_word_value(properties);
		produced_size = (produced_counter - consumed_counter) & max_word_value(properties);
		DBG("Pushed consumed_counter: 0x%" PRIx64, consumed_counter);
	}

	if (produced_size > properties.buf_size) {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(fmt::format(
			"Producer is more than a buffer ahead of the consumer: produced_counter={:#x}, consumed_counter={:#x}, buf_size={}",
			produced_counter,
			consumed_counter,
			properties.buf_size));
	}

	const auto subbuf_count =
		(produced_size + properties.subbuf_size - 1) / properties.subbuf_size;
	bool has_data = false;

	for (uint64_t i = 0; i < subbuf_count; i++) {
		const auto produced_counter_at_subbuf_start =
			(consumed_counter + (i * properties.subbuf_size)) &
			max_word_value(properties);

		bool is_copied;

		try {
			is_copied = copy_crash_subbuf(
				buffer, properties, fd_dest, produced_counter_at_subbuf_start);
		} catch (...) {
			std::throw_with_nested(lttng::runtime_error(
				fmt::format(
					"Failed to copy writer sub-buffer {}: produced_counter_at_subbuf_start={:#x}",
					subbuf_index(produced_counter_at_subbuf_start,
						     properties.buf_size,
						     properties.subbuf_size),
					produced_counter_at_subbuf_start),
				LTTNG_SOURCE_LOCATION()));
		}

		if (!is_copied) {
			break;
		}

		has_data = true;
	}

	return has_data;
}

int extract_file(int output_dir_fd,
		 const char *output_file,
		 int input_dir_fd,
		 const char *input_file)
{
	DBG("Extract file '%s'", input_file);

	const auto raw_fd_src = openat(input_dir_fd, input_file, O_RDONLY);
	if (raw_fd_src < 0) {
		PERROR("Error opening '%s' for reading", input_file);
		return -1;
	}

	lttng::input_stream_descriptor fd_src(raw_fd_src);

	try {
		const auto header = [&fd_src]() {
			try {
				return decode_crash_header(fd_src);
			} catch (...) {
				std::throw_with_nested(lttng::runtime_error(
					"Failed to decode the crash ABI header",
					LTTNG_SOURCE_LOCATION()));
			}
		}();
		if (!header) {
			return 1;
		}

		const crash_buffer buffer(std::move(fd_src), header->layout, header->mmap_length);

		const auto raw_fd_dest = openat(output_dir_fd,
						output_file,
						O_RDWR | O_CREAT | O_EXCL,
						S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
		if (raw_fd_dest < 0) {
			PERROR("Error opening '%s' for writing", output_file);
			return -1;
		}

		const lttng::output_stream_descriptor fd_dest(raw_fd_dest);

		lttng::scope_exit remove_output_file([output_dir_fd, output_file]() noexcept {
			if (unlinkat(output_dir_fd, output_file, 0)) {
				PERROR("Failed to remove output file '%s'", output_file);
			}
		});

		if (!copy_crash_data(buffer, header->properties, fd_dest)) {
			return -ENODATA;
		}

		remove_output_file.disarm();
		return 0;
	} catch (const std::exception& ex) {
		log_error_with_causes(ex, "Failed to extract buffer file `{}`", input_file);
		return -1;
	}
}

int extract_all_files(const char *output_path, const char *input_path)
{
	DIR *const input_dir = opendir(input_path);
	if (!input_dir) {
		PERROR("Cannot open '%s' path", input_path);
		return -1;
	}

	const lttng::scope_exit close_input_dir([input_dir, input_path]() noexcept {
		if (closedir(input_dir)) {
			PERROR("Failed to close directory '%s'", input_path);
		}
	});

	const auto input_dir_fd = dirfd(input_dir);
	if (input_dir_fd < 0) {
		PERROR("Failed to get the file descriptor of directory '%s'", input_path);
		return -1;
	}

	DIR *const output_dir = opendir(output_path);
	if (!output_dir) {
		PERROR("Cannot open '%s' path", output_path);
		return -1;
	}

	const lttng::scope_exit close_output_dir([output_dir, output_path]() noexcept {
		if (closedir(output_dir)) {
			PERROR("Failed to close directory '%s'", output_path);
		}
	});

	const auto output_dir_fd = dirfd(output_dir);
	if (output_dir_fd < 0) {
		PERROR("Failed to get the file descriptor of directory '%s'", output_path);
		return -1;
	}

	bool has_error = false;

	for (;;) {
		/* readdir() returns `nullptr` both at the end and on error. */
		errno = 0;
		const auto *const entry = readdir(input_dir);
		if (!entry) {
			if (errno != 0) {
				PERROR("Failed to read directory '%s'", input_path);
				has_error = true;
			}

			break;
		}

		const lttng::c_string_view file_name(entry->d_name);

		if (file_name == "." || file_name == ".." || file_name == "metadata") {
			continue;
		}

		const auto extract_ret =
			extract_file(output_dir_fd, file_name, input_dir_fd, file_name);
		if (extract_ret == -ENODATA) {
			DBG("No data in file '%s', skipping", entry->d_name);
		} else if (extract_ret < 0) {
			/* extract_file() logged the error. Extract the other streams anyway. */
			has_error = true;
		} else if (extract_ret > 0) {
			DBG("Skipping file '%s'", entry->d_name);
		}
	}

	return has_error ? -1 : 0;
}

int extract_one_trace(const char *output_path, const char *input_path)
{
	DBG("Extract crash trace '%s' into '%s'", input_path, output_path);

	try {
		copy_file(fmt::format("{}/metadata", output_path),
			  fmt::format("{}/metadata", input_path));
	} catch (const std::exception& ex) {
		log_error_with_causes(ex, "Failed to copy the metadata file of `{}`", input_path);
		return -1;
	}

	/* Extract each other file that has expected header */
	return extract_all_files(output_path, input_path);
}

int extract_trace_recursive(const std::string& output_path, const std::string& input_path)
{
	DIR *const dir = opendir(input_path.c_str());
	if (!dir) {
		PERROR("Cannot open '%s' path", input_path.c_str());
		return -1;
	}

	const lttng::scope_exit close_dir([dir]() noexcept {
		if (closedir(dir)) {
			PERROR("closedir");
		}
	});

	int has_warning = 0;

	for (;;) {
		/* readdir() returns `nullptr` both at the end and on error. */
		errno = 0;
		const auto *const entry = readdir(dir);
		if (!entry) {
			if (errno != 0) {
				PERROR("Failed to read directory '%s'", input_path.c_str());
				has_warning = true;
			}

			break;
		}

		const lttng::c_string_view entry_name(entry->d_name);

		if (entry_name == "." || entry_name == "..") {
			continue;
		}

		const auto entry_input_path = fmt::format("{}/{}", input_path, entry_name);
		struct stat st;

		if (stat(entry_input_path.c_str(), &st)) {
			PERROR("Failed to stat '%s'", entry_input_path.c_str());
			has_warning = true;
			continue;
		}

		if (S_ISDIR(st.st_mode)) {
			const auto entry_output_path =
				fmt::format("{}/{}", output_path, entry_name);

			if (mkdir(entry_output_path.c_str(), S_IRWXU | S_IRWXG)) {
				PERROR("Failed to create directory '%s'",
				       entry_output_path.c_str());
				has_warning = true;
				continue;
			}

			if (extract_trace_recursive(entry_output_path, entry_input_path)) {
				has_warning = true;
			}
		} else if (S_ISREG(st.st_mode)) {
			if (entry_name == "metadata") {
				if (extract_one_trace(output_path.c_str(), input_path.c_str())) {
					WARN("Error extracting trace '%s', continuing anyway.",
					     input_path.c_str());
					has_warning = true;
				}
			}
		}
	}

	return has_warning ? 1 : 0;
}

int delete_dir_recursive(const std::string& path)
{
	DIR *const dir = opendir(path.c_str());
	if (!dir) {
		PERROR("Cannot open '%s' path", path.c_str());
		return -errno;
	}

	const lttng::scope_exit close_dir([dir]() noexcept {
		if (closedir(dir)) {
			PERROR("closedir");
		}
	});

	const auto dir_fd = dirfd(dir);
	if (dir_fd < 0) {
		PERROR("dirfd");
		return -errno;
	}

	for (;;) {
		/* readdir() returns `nullptr` both at the end and on error. */
		errno = 0;
		const auto *const entry = readdir(dir);
		if (!entry) {
			if (errno != 0) {
				PERROR("Failed to read directory '%s'", path.c_str());
				return -1;
			}

			break;
		}

		const lttng::c_string_view entry_name(entry->d_name);

		if (entry_name == "." || entry_name == "..") {
			continue;
		}

		const auto entry_path = fmt::format("{}/{}", path, entry_name);
		struct stat st;

		if (stat(entry_path.c_str(), &st)) {
			PERROR("Failed to stat '%s'", entry_path.c_str());
			continue;
		}

		if (S_ISDIR(st.st_mode)) {
			const auto ret = delete_dir_recursive(entry_path);
			if (ret) {
				/* Error occurred, abort traversal. */
				return ret;
			}
		} else if (S_ISREG(st.st_mode)) {
			if (unlinkat(dir_fd, entry->d_name, 0)) {
				PERROR("Unlinking '%s'", entry_path.c_str());
				return -1;
			}
		} else {
			return -EINVAL;
		}
	}

	const auto ret = rmdir(path.c_str());
	if (ret) {
		PERROR("rmdir '%s'", path.c_str());
	}

	return ret;
}

int view_trace(const char *trace_path, char *viewer_path)
{
	struct sigaction ignore_action = {};
	ignore_action.sa_handler = SIG_IGN;
	sigemptyset(&ignore_action.sa_mask);

	struct sigaction original_sigint_action = {};
	struct sigaction original_sigquit_action = {};

	if (sigaction(SIGINT, &ignore_action, &original_sigint_action) ||
	    sigaction(SIGQUIT, &ignore_action, &original_sigquit_action)) {
		PERROR("Failed to ignore SIGINT and SIGQUIT while the viewer runs");
	}

	const auto restore_signal_actions = [&original_sigint_action,
					     &original_sigquit_action]() noexcept {
		(void) sigaction(SIGINT, &original_sigint_action, nullptr);
		(void) sigaction(SIGQUIT, &original_sigquit_action, nullptr);
	};
	const lttng::scope_exit restore_signal_actions_on_exit(
		[&restore_signal_actions]() noexcept { restore_signal_actions(); });

	const auto pid = fork();
	if (pid < 0) {
		PERROR("Failed to fork the viewer process");
		return -1;
	}

	if (pid == 0) {
		/* Let the viewer handle the signals. */
		restore_signal_actions();

		/*
		 * spawn_viewer() only returns on error. Don't return to run(), which
		 * would also remove the temporary directory.
		 */
		spawn_viewer(trace_path, viewer_path, false);
		_exit(EXIT_FAILURE);
	}

	int status;

	if (waitpid(pid, &status, 0) < 0) {
		PERROR("Failed to wait for the viewer process");
		return -1;
	}

	if (WIFSIGNALED(status)) {
		ERR("Viewer process was terminated by signal %d", WTERMSIG(status));
		return -1;
	} else if (WEXITSTATUS(status) != EXIT_SUCCESS) {
		ERR("Viewer process exited with status %d", WEXITSTATUS(status));
		return -1;
	}

	return 0;
}

/* Returns whether `path` and its contents were removed. */
bool remove_output_directory(const lttng::c_string_view path) noexcept
{
	try {
		return delete_dir_recursive(path) == 0;
	} catch (const std::exception& ex) {
		log_error_with_causes(ex, "Failed to delete `{}`", path);
		return false;
	}
}

/* Returns whether lttng-crash succeeded. */
bool run(int argc, char *argv[])
{
	const auto parse_ret = parse_args(argc, argv);
	if (parse_ret > 0) {
		/* Help, version, or option list. */
		return true;
	} else if (parse_ret < 0) {
		return false;
	}

	char temporary_path[] = "/tmp/lttng-crash-XXXXXX";
	lttng::c_string_view output_path;

	if (opt_output_path) {
		if (mkdir(opt_output_path, S_IRWXU | S_IRWXG)) {
			PERROR("Failed to create output directory '%s'", opt_output_path);
			return false;
		}

		output_path = opt_output_path;
	} else {
		output_path = mkdtemp(temporary_path);
		if (!output_path) {
			PERROR("Failed to create a temporary output directory");
			return false;
		}
	}

	/* Don't leave the output directory behind if the extraction fails. */
	lttng::scope_exit remove_output(
		[output_path]() noexcept { remove_output_directory(output_path); });

	int extract_ret;

	try {
		extract_ret = extract_trace_recursive(output_path, the_input_path);
	} catch (const std::exception& ex) {
		log_error_with_causes(ex, "Failed to extract `{}`", the_input_path);
		return false;
	}

	if (extract_ret < 0) {
		return false;
	}

	auto is_success = extract_ret == 0;

	if (opt_output_path) {
		remove_output.disarm();
		return is_success;
	}

	if (view_trace(output_path, opt_viewer_path)) {
		is_success = false;
	}

	remove_output.disarm();
	return remove_output_directory(output_path) && is_success;
}
} /* namespace */

int main(int argc, char *argv[])
{
	progname = argv[0] ? argv[0] : "lttng-crash";

	/* run() handles the expected errors; this just catches the rest. */
	try {
		return run(argc, argv) ? EXIT_SUCCESS : EXIT_FAILURE;
	} catch (const std::exception& ex) {
		log_error_with_causes(ex, "Unexpected error");
	} catch (...) {
		ERR("Unexpected error of unknown type");
	}

	return EXIT_FAILURE;
}
