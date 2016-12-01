/*
 * Copyright (C) 2011 David Goulet <david.goulet@polymtl.ca>
 * Copyright (C) 2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <byteswap.h>
#include <inttypes.h>
#include <stdbool.h>

#include <version.h>
#include <lttng/lttng.h>
#include <common/common.h>
#include <common/utils.h>

#define DEFAULT_VIEWER "babeltrace"

#define COPY_BUFLEN		4096
#define RB_CRASH_DUMP_ABI_LEN	32

#define RB_CRASH_DUMP_ABI_MAGIC_LEN	16

/*
 * The 128-bit magic number is xor'd in the process data so it does not
 * cause a false positive when searching for buffers by scanning memory.
 * The actual magic number is:
 *   0x17, 0x7B, 0xF1, 0x77, 0xBF, 0x17, 0x7B, 0xF1,
 *   0x77, 0xBF, 0x17, 0x7B, 0xF1, 0x77, 0xBF, 0x17,
 */
#define RB_CRASH_DUMP_ABI_MAGIC_XOR					\
	{								\
		0x17 ^ 0xFF, 0x7B ^ 0xFF, 0xF1 ^ 0xFF, 0x77 ^ 0xFF,	\
		0xBF ^ 0xFF, 0x17 ^ 0xFF, 0x7B ^ 0xFF, 0xF1 ^ 0xFF,	\
		0x77 ^ 0xFF, 0xBF ^ 0xFF, 0x17 ^ 0xFF, 0x7B ^ 0xFF,	\
		0xF1 ^ 0xFF, 0x77 ^ 0xFF, 0xBF ^ 0xFF, 0x17 ^ 0xFF,	\
	}

static const char *help_msg =
#ifdef LTTNG_EMBED_HELP
#include <lttng-crash.1.h>
#else
NULL
#endif
;

/*
 * Non-static to ensure the compiler does not optimize away the xor.
 */
uint8_t lttng_crash_expected_magic_xor[] = RB_CRASH_DUMP_ABI_MAGIC_XOR;

#define RB_CRASH_ENDIAN			0x1234
#define RB_CRASH_ENDIAN_REVERSE		0x3412

enum lttng_crash_type {
	LTTNG_CRASH_TYPE_UST = 0,
	LTTNG_CRASH_TYPE_KERNEL = 1,
};

/* LTTng ring buffer defines (copied) */

#define HALF_ULONG_BITS(wl)	(((wl) * CHAR_BIT) >> 1)

#define SB_ID_OFFSET_SHIFT(wl)	(HALF_ULONG_BITS(wl) + 1)
#define SB_ID_OFFSET_COUNT(wl)	(1UL << SB_ID_OFFSET_SHIFT(wl))
#define SB_ID_OFFSET_MASK(wl)	(~(SB_ID_OFFSET_COUNT(wl) - 1))
/*
 * Lowest bit of top word half belongs to noref. Used only for overwrite mode.
 */
#define SB_ID_NOREF_SHIFT(wl)	(SB_ID_OFFSET_SHIFT(wl) - 1)
#define SB_ID_NOREF_COUNT(wl)	(1UL << SB_ID_NOREF_SHIFT(wl))
#define SB_ID_NOREF_MASK(wl)	SB_ID_NOREF_COUNT(wl)
/*
 * In overwrite mode: lowest half of word is used for index.
 * Limit of 2^16 subbuffers per buffer on 32-bit, 2^32 on 64-bit.
 * In producer-consumer mode: whole word used for index.
 */
#define SB_ID_INDEX_SHIFT(wl)	0
#define SB_ID_INDEX_COUNT(wl)	(1UL << SB_ID_INDEX_SHIFT(wl))
#define SB_ID_INDEX_MASK(wl)	(SB_ID_NOREF_COUNT(wl) - 1)

enum rb_modes {
	RING_BUFFER_OVERWRITE = 0,      /* Overwrite when buffer full */
	RING_BUFFER_DISCARD = 1,        /* Discard when buffer full */
};

struct crash_abi_unknown {
	uint8_t magic[RB_CRASH_DUMP_ABI_MAGIC_LEN];
	uint64_t mmap_length;	/* Overall length of crash record */
	uint16_t endian;	/*
				 * { 0x12, 0x34 }: big endian
				 * { 0x34, 0x12 }: little endian
				 */
	uint16_t major;		/* Major number. */
	uint16_t minor;		/* Minor number. */
	uint8_t word_size;	/* Word size (bytes). */
	uint8_t layout_type;	/* enum lttng_crash_layout */
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

	uint64_t buf_size;	/* Size of the buffer */
	uint64_t subbuf_size;	/* Sub-buffer size */
	uint64_t num_subbuf;	/* Number of sub-buffers for writer */
	uint32_t mode;		/* Buffer mode: 0: overwrite, 1: discard */
} __attribute__((packed));

struct lttng_crash_layout {
	struct {
		int prod_offset, consumed_offset,
			commit_hot_array, commit_hot_seq,
			buf_wsb_array, buf_wsb_id,
			sb_array, sb_array_shmp_offset,
			sb_backend_p_offset, content_size,
			packet_size;
	} offset;
	struct {
		int prod_offset, consumed_offset,
			commit_hot_seq, buf_wsb_id,
			sb_array_shmp_offset, sb_backend_p_offset,
			content_size, packet_size;
	} length;
	struct {
		int commit_hot_array, buf_wsb_array, sb_array;
	} stride;

	int reverse_byte_order;
	int word_size;

	uint64_t mmap_length;	/* Length of crash record */
	uint64_t buf_size;	/* Size of the buffer */
	uint64_t subbuf_size;	/* Sub-buffer size */
	uint64_t num_subbuf;	/* Number of sub-buffers for writer */
	uint32_t mode;		/* Buffer mode: 0: overwrite, 1: discard */
};

/* Variables */
static char *progname,
	*opt_viewer_path = NULL,
	*opt_output_path = NULL;

static char *input_path;

int lttng_opt_quiet, lttng_opt_verbose, lttng_opt_mi;

enum {
	OPT_DUMP_OPTIONS,
};

/* Getopt options. No first level command. */
static struct option long_options[] = {
	{ "version",		0, NULL, 'V' },
	{ "help",		0, NULL, 'h' },
	{ "verbose",		0, NULL, 'v' },
	{ "viewer",		1, NULL, 'e' },
	{ "extract",		1, NULL, 'x' },
	{ "list-options",	0, NULL, OPT_DUMP_OPTIONS },
	{ NULL, 0, NULL, 0 },
};

static void usage(void)
{
	int ret = utils_show_help(1, "lttng-crash", help_msg);

	if (ret) {
		ERR("Cannot show --help for `lttng-crash`");
		perror("exec");
		exit(EXIT_FAILURE);
	}
}

static void version(FILE *ofp)
{
	fprintf(ofp, "%s (LTTng Crash Trace Viewer) " VERSION " - " VERSION_NAME
"%s\n",
			progname,
			GIT_VERSION[0] == '\0' ? "" : " - " GIT_VERSION);
}

/*
 *  list_options
 *
 *  List options line by line. This is mostly for bash auto completion and to
 *  avoid difficult parsing.
 */
static void list_options(FILE *ofp)
{
	int i = 0;
	struct option *option = NULL;

	option = &long_options[i];
	while (option->name != NULL) {
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
static int parse_args(int argc, char **argv)
{
	int opt, ret = 0;

	if (argc < 2) {
		usage();
		exit(EXIT_FAILURE);
	}

	while ((opt = getopt_long(argc, argv, "+Vhve:x:", long_options, NULL)) != -1) {
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

	if (!opt_viewer_path) {
		opt_viewer_path = DEFAULT_VIEWER;
	}

	/* No leftovers, or more than one input path, print usage and quit */
	if (argc - optind != 1) {
		ERR("Command-line error: Specify exactly one input path");
		goto error;
	}

	input_path = argv[optind];
end:
	return ret;

error:
	return -1;
}

static
int copy_file(const char *file_dest, const char *file_src)
{
	int fd_src = -1, fd_dest = -1;
	ssize_t readlen, writelen;
	char buf[COPY_BUFLEN];
	int ret;

	DBG("Copy metadata file '%s' into '%s'", file_src, file_dest);

	fd_src = open(file_src, O_RDONLY);
	if (fd_src < 0) {
		PERROR("Error opening %s for reading", file_src);
		ret = -errno;
		goto error;
	}
	fd_dest = open(file_dest, O_RDWR | O_CREAT | O_EXCL,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (fd_dest < 0) {
		PERROR("Error opening %s for writing", file_dest);
		ret = -errno;
		goto error;
	}

	for (;;) {
		readlen = lttng_read(fd_src, buf, COPY_BUFLEN);
		if (readlen < 0) {
			PERROR("Error reading input file");
			ret = -1;
			goto error;
		}
		if (!readlen) {
			break;
		}
		writelen = lttng_write(fd_dest, buf, readlen);
		if (writelen < readlen) {
			PERROR("Error writing to output file");
			ret = -1;
			goto error;
		}
	}

	ret = 0;
error:
	if (fd_src >= 0) {
		if (close(fd_src) < 0) {
			PERROR("Error closing %s", file_src);
		}
	}

	if (fd_dest >= 0) {
		if (close(fd_dest) < 0) {
			PERROR("Error closing %s", file_dest);
		}
	}
	return ret;
}

static
uint64_t _crash_get_field(const struct lttng_crash_layout *layout,
		const char *ptr, size_t size)
{
	switch (size) {
	case 1:	return *(uint8_t *) ptr;
	case 2:	if (layout->reverse_byte_order) {
			return __bswap_16(*(uint16_t *) ptr);
		} else {
			return *(uint16_t *) ptr;

		}
	case 4:	if (layout->reverse_byte_order) {
			return __bswap_32(*(uint32_t *) ptr);
		} else {
			return *(uint32_t *) ptr;

		}
	case 8:	if (layout->reverse_byte_order) {
			return __bswap_64(*(uint64_t *) ptr);
		} else {
			return *(uint64_t *) ptr;
		}
	default:
		abort();
		return -1;
	}

}

#define crash_get_field(layout, map, name)				\
	_crash_get_field(layout, (map) + (layout)->offset.name,		\
		layout->length.name)

#define crash_get_array_field(layout, map, array_name, idx, field_name)	\
	_crash_get_field(layout,					\
		(map) + (layout)->offset.array_name			\
			+ (idx * (layout)->stride.array_name)		\
			+ (layout)->offset.field_name,			\
		(layout)->length.field_name)

#define crash_get_hdr_raw_field(layout, hdr, name)	((hdr)->name)

#define crash_get_hdr_field(layout, hdr, name)				\
	_crash_get_field(layout, (const char *) &(hdr)->name,		\
		sizeof((hdr)->name))

#define crash_get_layout(layout, hdr, name)				\
	do {								\
		(layout)->name = crash_get_hdr_field(layout, hdr,	\
					name);				\
		DBG("layout.%s = %" PRIu64, #name,			\
			(uint64_t) (layout)->name);			\
	} while (0)

static
int get_crash_layout_0_0(struct lttng_crash_layout *layout,
		char *map)
{
	const struct crash_abi_0_0 *abi = (const struct crash_abi_0_0 *) map;

	crash_get_layout(layout, abi, offset.prod_offset);
	crash_get_layout(layout, abi, offset.consumed_offset);
	crash_get_layout(layout, abi, offset.commit_hot_array);
	crash_get_layout(layout, abi, offset.commit_hot_seq);
	crash_get_layout(layout, abi, offset.buf_wsb_array);
	crash_get_layout(layout, abi, offset.buf_wsb_id);
	crash_get_layout(layout, abi, offset.sb_array);
	crash_get_layout(layout, abi, offset.sb_array_shmp_offset);
	crash_get_layout(layout, abi, offset.sb_backend_p_offset);
	crash_get_layout(layout, abi, offset.content_size);
	crash_get_layout(layout, abi, offset.packet_size);

	crash_get_layout(layout, abi, length.prod_offset);
	crash_get_layout(layout, abi, length.consumed_offset);
	crash_get_layout(layout, abi, length.commit_hot_seq);
	crash_get_layout(layout, abi, length.buf_wsb_id);
	crash_get_layout(layout, abi, length.sb_array_shmp_offset);
	crash_get_layout(layout, abi, length.sb_backend_p_offset);
	crash_get_layout(layout, abi, length.content_size);
	crash_get_layout(layout, abi, length.packet_size);

	crash_get_layout(layout, abi, stride.commit_hot_array);
	crash_get_layout(layout, abi, stride.buf_wsb_array);
	crash_get_layout(layout, abi, stride.sb_array);

	crash_get_layout(layout, abi, buf_size);
	crash_get_layout(layout, abi, subbuf_size);
	crash_get_layout(layout, abi, num_subbuf);
	crash_get_layout(layout, abi, mode);

	return 0;
}

static
void print_dbg_magic(const uint8_t *magic)
{
	DBG("magic: 0x%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X",
		magic[0], magic[1], magic[2], magic[3],
		magic[4], magic[5], magic[6], magic[7],
		magic[8], magic[9], magic[10], magic[11],
		magic[12], magic[13], magic[14], magic[15]);
}

static
int check_magic(const uint8_t *magic)
{
	int i;

	for (i = 0; i < RB_CRASH_DUMP_ABI_MAGIC_LEN; i++) {
		if ((magic[i] ^ 0xFF) != lttng_crash_expected_magic_xor[i]) {
			return -1;
		}
	}
	return 0;
}

static
int get_crash_layout(struct lttng_crash_layout *layout, int fd)
{
	char *map;
	int ret = 0, unmapret;
	const uint8_t *magic;
	uint64_t mmap_length;
	uint16_t major, minor;
	uint8_t word_size;
	const struct crash_abi_unknown *abi;
	uint16_t endian;
	enum lttng_crash_type layout_type;

	map = mmap(NULL, RB_CRASH_DUMP_ABI_LEN, PROT_READ, MAP_PRIVATE,
		fd, 0);
	if (map == MAP_FAILED) {
		PERROR("Mapping file");
		return -1;
	}
	abi = (const struct crash_abi_unknown *) map;
	magic = crash_get_hdr_raw_field(layout, abi, magic);
	print_dbg_magic(magic);
	if (check_magic(magic)) {
		DBG("Unknown magic number");
		ret = 1;	/* positive return value, skip */
		goto end;
	}
	endian = crash_get_hdr_field(layout, abi, endian);
	switch (endian) {
	case RB_CRASH_ENDIAN:
		break;
	case RB_CRASH_ENDIAN_REVERSE:
		layout->reverse_byte_order = 1;
		break;
	default:
		DBG("Unknown endianness value: 0x%X", (unsigned int) endian);
		ret = 1;	/* positive return value, skip */
		goto end;
	}
	layout_type = (enum lttng_crash_type) crash_get_hdr_field(layout, abi, layout_type);
	switch (layout_type) {
	case LTTNG_CRASH_TYPE_UST:
		break;
	case LTTNG_CRASH_TYPE_KERNEL:
		ERR("lttng-modules buffer layout support not implemented");
		ret = 1;	/* positive return value, skip */
		goto end;
	default:
		ERR("Unknown layout type %u", (unsigned int) layout_type);
		ret = 1;	/* positive return value, skip */
		goto end;
	}
	mmap_length = crash_get_hdr_field(layout, abi, mmap_length);
	DBG("mmap_length: %" PRIu64, mmap_length);
	layout->mmap_length = mmap_length;
	major = crash_get_hdr_field(layout, abi, major);
	DBG("major: %u", major);
	minor = crash_get_hdr_field(layout, abi, minor);
	DBG("minor: %u", minor);
	word_size = crash_get_hdr_field(layout, abi, word_size);
	DBG("word_size: %u", word_size);
	switch (major) {
	case 0:
		switch (minor) {
		case 0:
			ret = get_crash_layout_0_0(layout, map);
			if (ret)
				goto end;
			break;
		default:
			ret = -1;
			ERR("Unsupported crash ABI %u.%u\n", major, minor);
			goto end;
		}
		break;
	default:
		ERR("Unsupported crash ABI %u.%u\n", major, minor);
		ret = -1;
		goto end;
	}
	layout->word_size = word_size;
end:
	unmapret = munmap(map, RB_CRASH_DUMP_ABI_LEN);
	if (unmapret) {
		PERROR("munmap");
	}
	return ret;
}

/* buf_trunc mask selects only the buffer number. */
static inline
uint64_t buf_trunc(uint64_t offset, uint64_t buf_size)
{
	return offset & ~(buf_size - 1);
}

/* subbuf_trunc mask selects the subbuffer number. */
static inline
uint64_t subbuf_trunc(uint64_t offset, uint64_t subbuf_size)
{
	return offset & ~(subbuf_size - 1);
}

/* buf_offset mask selects only the offset within the current buffer. */
static inline
uint64_t buf_offset(uint64_t offset, uint64_t buf_size)
{
	return offset & (buf_size - 1);
}

/* subbuf_offset mask selects the offset within the current subbuffer. */
static inline
uint64_t subbuf_offset(uint64_t offset, uint64_t subbuf_size)
{
	return offset & (subbuf_size - 1);
}

/* subbuf_index returns the index of the current subbuffer within the buffer. */
static inline
uint64_t subbuf_index(uint64_t offset, uint64_t buf_size, uint64_t subbuf_size)
{
	return buf_offset(offset, buf_size) / subbuf_size;
}

static inline
uint64_t subbuffer_id_get_index(uint32_t mode, uint64_t id,
		unsigned int wl)
{
	if (mode == RING_BUFFER_OVERWRITE)
		return id & SB_ID_INDEX_MASK(wl);
	else
		return id;
}

static
int copy_crash_subbuf(const struct lttng_crash_layout *layout,
		int fd_dest, char *buf, uint64_t offset)
{
	uint64_t buf_size, subbuf_size, num_subbuf, sbidx, id,
		sb_bindex, rpages_offset, p_offset, seq_cc,
		committed, commit_count_mask, consumed_cur,
		packet_size;
	char *subbuf_ptr;
	ssize_t writelen;

	/*
	 * Get the current subbuffer by applying the proper mask to
	 * "offset", and looking up the subbuf location within the
	 * source file buf.
	 */

	buf_size = layout->buf_size;
	subbuf_size = layout->subbuf_size;
	num_subbuf = layout->num_subbuf;

	switch (layout->word_size) {
	case 4:	commit_count_mask = 0xFFFFFFFFULL / num_subbuf;
		break;
	case 8:	commit_count_mask = 0xFFFFFFFFFFFFFFFFULL / num_subbuf;
		break;
	default:
		ERR("Unsupported word size: %u",
			(unsigned int) layout->word_size);
		return -EINVAL;
	}

	DBG("Copy crash subbuffer at offset %" PRIu64, offset);
	sbidx = subbuf_index(offset, buf_size, subbuf_size);

	/*
	 * Find where the seq cc is located. Compute length of data to
	 * copy.
	 */
	seq_cc = crash_get_array_field(layout, buf, commit_hot_array,
		sbidx, commit_hot_seq);
	consumed_cur = crash_get_field(layout, buf, consumed_offset);

	/*
	 * Check that the buffer we are getting is after or at
	 * consumed_cur position.
	 */
	if ((long) subbuf_trunc(offset, subbuf_size)
			- (long) subbuf_trunc(consumed_cur, subbuf_size) < 0) {
		DBG("No data: position is before consumed_cur");
		goto nodata;
	}

	/*
	 * Check if subbuffer has been fully committed.
	 */
	if (((seq_cc - subbuf_size) & commit_count_mask)
			- (buf_trunc(offset, buf_size) / num_subbuf)
			== 0) {
		committed = subbuf_size;
	} else {
		committed = subbuf_offset(seq_cc, subbuf_size);
		if (!committed) {
			DBG("No data committed, seq_cc: %" PRIu64, seq_cc);
			goto nodata;
		}
	}

	/* Find actual physical offset in subbuffer table */
	id = crash_get_array_field(layout, buf, buf_wsb_array,
		sbidx, buf_wsb_id);
	sb_bindex = subbuffer_id_get_index(layout->mode, id,
		layout->word_size);
	rpages_offset = crash_get_array_field(layout, buf, sb_array,
		sb_bindex, sb_array_shmp_offset);
	p_offset = crash_get_field(layout, buf + rpages_offset,
		sb_backend_p_offset);
	subbuf_ptr = buf + p_offset;

	if (committed == subbuf_size) {
		/*
		 * Packet header can be used.
		 */
		if (layout->length.packet_size) {
			memcpy(&packet_size,
				subbuf_ptr + layout->offset.packet_size,
				layout->length.packet_size);
			if (layout->reverse_byte_order) {
				packet_size = __bswap_64(packet_size);
			}
			packet_size /= CHAR_BIT;
		} else {
			packet_size = subbuf_size;
		}
	} else {
		uint64_t patch_size;

		/*
		 * Find where to patch the sub-buffer header with actual
		 * readable data len and packet len, derived from seq
		 * cc. Patch it in our in-memory copy.
		 */
		patch_size = committed * CHAR_BIT;
		if (layout->reverse_byte_order) {
			patch_size = __bswap_64(patch_size);
		}
		if (layout->length.content_size) {
			memcpy(subbuf_ptr + layout->offset.content_size,
				&patch_size, layout->length.content_size);
		}
		if (layout->length.packet_size) {
			memcpy(subbuf_ptr + layout->offset.packet_size,
				&patch_size, layout->length.packet_size);
		}
		packet_size = committed;
	}

	/*
	 * Copy packet into fd_dest.
	 */
	writelen = lttng_write(fd_dest, subbuf_ptr, packet_size);
	if (writelen < packet_size) {
		PERROR("Error writing to output file");
		return -1;
	}
	DBG("Copied %" PRIu64 " bytes of data", packet_size);
	return 0;

nodata:
	return -ENODATA;
}

static
int copy_crash_data(const struct lttng_crash_layout *layout, int fd_dest,
		int fd_src)
{
	char *buf;
	int ret = 0, has_data = 0;
	struct stat statbuf;
	size_t src_file_len;
	uint64_t prod_offset, consumed_offset;
	uint64_t offset, subbuf_size;
	ssize_t readlen;

	ret = fstat(fd_src, &statbuf);
	if (ret) {
		return ret;
	}
	src_file_len = layout->mmap_length;
	buf = zmalloc(src_file_len);
	if (!buf) {
		return -1;
	}
	readlen = lttng_read(fd_src, buf, src_file_len);
	if (readlen < 0) {
		PERROR("Error reading input file");
		ret = -1;
		goto end;
	}

	prod_offset = crash_get_field(layout, buf, prod_offset);
	DBG("prod_offset: 0x%" PRIx64, prod_offset);
	consumed_offset = crash_get_field(layout, buf, consumed_offset);
	DBG("consumed_offset: 0x%" PRIx64, consumed_offset);
	subbuf_size = layout->subbuf_size;

	for (offset = consumed_offset; offset < prod_offset;
			offset += subbuf_size) {
		ret = copy_crash_subbuf(layout, fd_dest, buf, offset);
		if (!ret) {
			has_data = 1;
		}
		if (ret) {
			goto end;
		}
	}
end:
	free(buf);
	if (ret && ret != -ENODATA) {
		return ret;
	}
	if (has_data) {
		return 0;
	} else {
		return -ENODATA;
	}
}

static
int extract_file(int output_dir_fd, const char *output_file,
		int input_dir_fd, const char *input_file)
{
	int fd_dest, fd_src, ret = 0, closeret;
	struct lttng_crash_layout layout;

	layout.reverse_byte_order = 0;	/* For reading magic number */

	DBG("Extract file '%s'", input_file);
	fd_src = openat(input_dir_fd, input_file, O_RDONLY);
	if (fd_src < 0) {
		PERROR("Error opening '%s' for reading",
			input_file);
		ret = -1;
		goto end;
	}

	/* Query the crash ABI layout */
	ret = get_crash_layout(&layout, fd_src);
	if (ret) {
		goto close_src;
	}

	fd_dest = openat(output_dir_fd, output_file,
			O_RDWR | O_CREAT | O_EXCL,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (fd_dest < 0) {
		PERROR("Error opening '%s' for writing",
			output_file);
		ret = -1;
		goto close_src;
	}

	ret = copy_crash_data(&layout, fd_dest, fd_src);
	if (ret) {
		goto close_dest;
	}

close_dest:
	closeret = close(fd_dest);
	if (closeret) {
		PERROR("close");
	}
	if (ret == -ENODATA) {
		closeret = unlinkat(output_dir_fd, output_file, 0);
		if (closeret) {
			PERROR("unlinkat");
		}
	}
close_src:
	closeret = close(fd_src);
	if (closeret) {
		PERROR("close");
	}
end:
	return ret;
}

static
int extract_all_files(const char *output_path,
		const char *input_path)
{
	DIR *input_dir, *output_dir;
	int input_dir_fd, output_dir_fd, ret = 0, closeret;
	struct dirent *entry;	/* input */

	/* Open input directory */
	input_dir = opendir(input_path);
	if (!input_dir) {
		PERROR("Cannot open '%s' path", input_path);
		return -1;
	}
	input_dir_fd = dirfd(input_dir);
	if (input_dir_fd < 0) {
		PERROR("dirfd");
		return -1;
	}

	/* Open output directory */
	output_dir = opendir(output_path);
	if (!output_dir) {
		PERROR("Cannot open '%s' path", output_path);
		return -1;
	}
	output_dir_fd = dirfd(output_dir);
	if (output_dir_fd < 0) {
		PERROR("dirfd");
		return -1;
	}

	while ((entry = readdir(input_dir))) {
		if (!strcmp(entry->d_name, ".")
				|| !strcmp(entry->d_name, ".."))
			continue;
		ret = extract_file(output_dir_fd, entry->d_name,
			input_dir_fd, entry->d_name);
		if (ret == -ENODATA) {
			DBG("No data in file '%s', skipping", entry->d_name);
			ret = 0;
			continue;
		} else if (ret < 0) {
			break;
		} else if (ret > 0) {
			DBG("Skipping file '%s'", entry->d_name);
			ret = 0;
			continue;
		}
	}
	closeret = closedir(output_dir);
	if (closeret) {
		PERROR("closedir");
	}
	closeret = closedir(input_dir);
	if (closeret) {
		PERROR("closedir");
	}
	return ret;
}

static
int extract_one_trace(const char *output_path,
		const char *input_path)
{
	char dest[PATH_MAX], src[PATH_MAX];
	int ret;

	DBG("Extract crash trace '%s' into '%s'", input_path, output_path);

	/* Copy metadata */
	strncpy(dest, output_path, PATH_MAX);
	dest[PATH_MAX - 1] = '\0';
	strncat(dest, "/metadata", PATH_MAX - strlen(dest) - 1);

	strncpy(src, input_path, PATH_MAX);
	src[PATH_MAX - 1] = '\0';
	strncat(src, "/metadata", PATH_MAX - strlen(dest) - 1);

	ret = copy_file(dest, src);
	if (ret) {
		return ret;
	}

	/* Extract each other file that has expected header */
	return extract_all_files(output_path, input_path);
}

static
int extract_trace_recursive(const char *output_path,
		const char *input_path)
{
	DIR *dir;
	int dir_fd, ret = 0, closeret;
	struct dirent *entry;
	size_t path_len;
	int has_warning = 0;

	/* Open directory */
	dir = opendir(input_path);
	if (!dir) {
		PERROR("Cannot open '%s' path", input_path);
		return -1;
	}

	path_len = strlen(input_path);

	dir_fd = dirfd(dir);
	if (dir_fd < 0) {
		PERROR("dirfd");
		return -1;
	}

	while ((entry = readdir(dir))) {
		struct stat st;
		size_t name_len;
		char filename[PATH_MAX];

		if (!strcmp(entry->d_name, ".")
				|| !strcmp(entry->d_name, "..")) {
			continue;
		}

		name_len = strlen(entry->d_name);
		if (path_len + name_len + 2 > sizeof(filename)) {
			ERR("Failed to remove file: path name too long (%s/%s)",
				input_path, entry->d_name);
			continue;
		}

		if (snprintf(filename, sizeof(filename), "%s/%s",
				input_path, entry->d_name) < 0) {
			ERR("Failed to format path.");
			continue;
		}

		if (stat(filename, &st)) {
			PERROR("stat");
			continue;
		}

		if (S_ISDIR(st.st_mode)) {
			char output_subpath[PATH_MAX];
			char input_subpath[PATH_MAX];

			strncpy(output_subpath, output_path,
				sizeof(output_subpath));
			output_subpath[sizeof(output_subpath) - 1] = '\0';
			strncat(output_subpath, "/",
				sizeof(output_subpath) - strlen(output_subpath) - 1);
			strncat(output_subpath, entry->d_name,
				sizeof(output_subpath) - strlen(output_subpath) - 1);

			ret = mkdir(output_subpath, S_IRWXU | S_IRWXG);
			if (ret) {
				PERROR("mkdir");
				has_warning = 1;
				goto end;
			}

			strncpy(input_subpath, input_path,
				sizeof(input_subpath));
			input_subpath[sizeof(input_subpath) - 1] = '\0';
			strncat(input_subpath, "/",
				sizeof(input_subpath) - strlen(input_subpath) - 1);
			strncat(input_subpath, entry->d_name,
				sizeof(input_subpath) - strlen(input_subpath) - 1);

			ret = extract_trace_recursive(output_subpath,
				input_subpath);
			if (ret) {
				has_warning = 1;
			}
		} else if (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
			if (!strcmp(entry->d_name, "metadata")) {
				ret = extract_one_trace(output_path,
					input_path);
				if (ret) {
					WARN("Error extracting trace '%s', continuing anyway.",
						input_path);
					has_warning = 1;
				}
			}
		} else {
			has_warning = 1;
			goto end;
		}
	}
end:
	closeret = closedir(dir);
	if (closeret) {
		PERROR("closedir");
	}
	return has_warning;
}

static
int delete_dir_recursive(const char *path)
{
	DIR *dir;
	int dir_fd, ret = 0, closeret;
	size_t path_len;
	struct dirent *entry;

	/* Open trace directory */
	dir = opendir(path);
	if (!dir) {
		PERROR("Cannot open '%s' path", path);
		ret = -errno;
	        goto end;
	}

	path_len = strlen(path);

	dir_fd = dirfd(dir);
	if (dir_fd < 0) {
		PERROR("dirfd");
		ret = -errno;
		goto end;
	}

	while ((entry = readdir(dir))) {
		struct stat st;
		size_t name_len;
		char filename[PATH_MAX];

		if (!strcmp(entry->d_name, ".")
				|| !strcmp(entry->d_name, "..")) {
			continue;
		}

		name_len = strlen(entry->d_name);
		if (path_len + name_len + 2 > sizeof(filename)) {
			ERR("Failed to remove file: path name too long (%s/%s)",
				path, entry->d_name);
			continue;
		}

		if (snprintf(filename, sizeof(filename), "%s/%s",
				path, entry->d_name) < 0) {
			ERR("Failed to format path.");
			continue;
		}

		if (stat(filename, &st)) {
			PERROR("stat");
			continue;
		}

		if (S_ISDIR(st.st_mode)) {
			char *subpath = zmalloc(PATH_MAX);

			if (!subpath) {
				PERROR("zmalloc path");
				ret = -1;
				goto end;
			}
			strncpy(subpath, path, PATH_MAX);
			subpath[PATH_MAX - 1] = '\0';
			strncat(subpath, "/",
				        PATH_MAX - strlen(subpath) - 1);
			strncat(subpath, entry->d_name,
				        PATH_MAX - strlen(subpath) - 1);

			ret = delete_dir_recursive(subpath);
			free(subpath);
			if (ret) {
				/* Error occurred, abort traversal. */
				goto end;
			}
		} else if (S_ISREG(st.st_mode)) {
			ret = unlinkat(dir_fd, entry->d_name, 0);
			if (ret) {
				PERROR("Unlinking '%s'", entry->d_name);
				goto end;
			}
		} else {
			ret = -EINVAL;
			goto end;
		}
	}
end:
	if (!ret) {
		ret = rmdir(path);
		if (ret) {
			PERROR("rmdir '%s'", path);
		}
	}
	closeret = closedir(dir);
	if (closeret) {
		PERROR("closedir");
	}
	return ret;
}

static
int view_trace(const char *viewer_path, const char *trace_path)
{
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		/* Error */
		PERROR("fork");
		return -1;
	} else if (pid > 0) {
		/* Parent */
		int status;

		pid = waitpid(pid, &status, 0);
		if (pid < 0 || !WIFEXITED(status)) {
			return -1;
		}
	} else {
		/* Child */
		int ret;

		ret = execlp(viewer_path, viewer_path,
			trace_path, (char *) NULL);
		if (ret) {
			PERROR("execlp");
			exit(EXIT_FAILURE);
		}
		exit(EXIT_SUCCESS);	/* Never reached */
	}
	return 0;
}

/*
 *  main
 */
int main(int argc, char *argv[])
{
	int ret;
	bool has_warning = false;
	const char *output_path = NULL;
	char tmppath[] = "/tmp/lttng-crash-XXXXXX";

	progname = argv[0] ? argv[0] : "lttng-crash";

	ret = parse_args(argc, argv);
	if (ret > 0) {
		goto end;
	} else if (ret < 0) {
		has_warning = true;
		goto end;
	}

	if (opt_output_path) {
		output_path = opt_output_path;
		ret = mkdir(output_path, S_IRWXU | S_IRWXG);
		if (ret) {
			PERROR("mkdir");
			has_warning = true;
			goto end;
		}
	} else {
		output_path = mkdtemp(tmppath);
		if (!output_path) {
			PERROR("mkdtemp");
			has_warning = true;
			goto end;
		}
	}

	ret = extract_trace_recursive(output_path, input_path);
	if (ret < 0) {
		has_warning = true;
		goto end;
	} else if (ret > 0) {
		/* extract_trace_recursive reported a warning. */
		has_warning = true;
	}
	if (!opt_output_path) {
		/* View trace */
		ret = view_trace(opt_viewer_path, output_path);
		if (ret) {
			has_warning = true;
		}
		/* unlink temporary trace */
		ret = delete_dir_recursive(output_path);
		if (ret) {
			has_warning = true;
		}
	}
end:
	exit(has_warning ? EXIT_FAILURE : EXIT_SUCCESS);
}
