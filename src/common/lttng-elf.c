/*
 * Copyright (C) 2015 Antoine Busque <abusque@efficios.com>
 * Copyright (C) 2017 Francis Deslauriers <francis.deslauriers@efficios.com>
 * Copyright (C) 2017 Erica Bugden <erica.bugden@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 */

#include <common/compat/endian.h>
#include <common/error.h>
#include <common/lttng-elf.h>
#include <common/macros.h>
#include <common/readwrite.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <elf.h>

#define BUF_LEN	4096
#define TEXT_SECTION_NAME 	".text"
#define SYMBOL_TAB_SECTION_NAME ".symtab"
#define STRING_TAB_SECTION_NAME ".strtab"
#define DYNAMIC_SYMBOL_TAB_SECTION_NAME ".dynsym"
#define DYNAMIC_STRING_TAB_SECTION_NAME ".dynstr"
#define NOTE_STAPSDT_SECTION_NAME ".note.stapsdt"
#define NOTE_STAPSDT_NAME "stapsdt"
#define NOTE_STAPSDT_TYPE 3
#define MAX_SECTION_DATA_SIZE   512 * 1024 * 1024

#if BYTE_ORDER == LITTLE_ENDIAN
#define NATIVE_ELF_ENDIANNESS ELFDATA2LSB
#else
#define NATIVE_ELF_ENDIANNESS ELFDATA2MSB
#endif

#define next_4bytes_boundary(x) (typeof(x)) ((((uint64_t)x) + 3) & ~0x03)

#define bswap(x)				\
	do {					\
		switch (sizeof(x)) {		\
		case 8:				\
			x = be64toh((uint64_t)x);		\
			break;			\
		case 4:				\
			x = be32toh((uint32_t)x);		\
			break;			\
		case 2:				\
			x = be16toh((uint16_t)x);		\
			break;			\
		case 1:				\
			break;			\
		default:			\
			abort();		\
		}				\
	} while (0)

#define bswap_shdr(shdr)	    \
	do {				    \
		bswap((shdr).sh_name);	    \
		bswap((shdr).sh_type);	    \
		bswap((shdr).sh_flags);	    \
		bswap((shdr).sh_addr);	    \
		bswap((shdr).sh_offset);    \
		bswap((shdr).sh_size);	    \
		bswap((shdr).sh_link);	    \
		bswap((shdr).sh_info);	    \
		bswap((shdr).sh_addralign); \
		bswap((shdr).sh_entsize);   \
	} while (0)

#define bswap_ehdr(ehdr)				\
	do {						\
		bswap((ehdr).e_type);			\
		bswap((ehdr).e_machine);		\
		bswap((ehdr).e_version);		\
		bswap((ehdr).e_entry);			\
		bswap((ehdr).e_phoff);			\
		bswap((ehdr).e_shoff);			\
		bswap((ehdr).e_flags);			\
		bswap((ehdr).e_ehsize);			\
		bswap((ehdr).e_phentsize);		\
		bswap((ehdr).e_phnum);			\
		bswap((ehdr).e_shentsize);		\
		bswap((ehdr).e_shnum);			\
		bswap((ehdr).e_shstrndx);		\
	} while (0)

#define copy_shdr(src_shdr, dst_shdr)					\
	do {								\
		(dst_shdr).sh_name = (src_shdr).sh_name;		\
		(dst_shdr).sh_type = (src_shdr).sh_type;		\
		(dst_shdr).sh_flags = (src_shdr).sh_flags;		\
		(dst_shdr).sh_addr = (src_shdr).sh_addr;		\
		(dst_shdr).sh_offset = (src_shdr).sh_offset;		\
		(dst_shdr).sh_size = (src_shdr).sh_size;		\
		(dst_shdr).sh_link = (src_shdr).sh_link;		\
		(dst_shdr).sh_info = (src_shdr).sh_info;		\
		(dst_shdr).sh_addralign = (src_shdr).sh_addralign;	\
		(dst_shdr).sh_entsize = (src_shdr).sh_entsize;		\
	} while (0)

#define copy_ehdr(src_ehdr, dst_ehdr)					\
	do {								\
		(dst_ehdr).e_type = (src_ehdr).e_type;			\
		(dst_ehdr).e_machine = (src_ehdr).e_machine;		\
		(dst_ehdr).e_version = (src_ehdr).e_version;		\
		(dst_ehdr).e_entry = (src_ehdr).e_entry;		\
		(dst_ehdr).e_phoff = (src_ehdr).e_phoff;		\
		(dst_ehdr).e_shoff = (src_ehdr).e_shoff;		\
		(dst_ehdr).e_flags = (src_ehdr).e_flags;		\
		(dst_ehdr).e_ehsize = (src_ehdr).e_ehsize;		\
		(dst_ehdr).e_phentsize = (src_ehdr).e_phentsize;	\
		(dst_ehdr).e_phnum = (src_ehdr).e_phnum;		\
		(dst_ehdr).e_shentsize = (src_ehdr).e_shentsize;	\
		(dst_ehdr).e_shnum = (src_ehdr).e_shnum;		\
		(dst_ehdr).e_shstrndx = (src_ehdr).e_shstrndx;		\
	} while (0)

#define copy_sym(src_sym, dst_sym)			\
	do {						\
		dst_sym.st_name = src_sym.st_name;	\
		dst_sym.st_info = src_sym.st_info;	\
		dst_sym.st_other = src_sym.st_other;	\
		dst_sym.st_shndx = src_sym.st_shndx;	\
		dst_sym.st_value = src_sym.st_value;	\
		dst_sym.st_size = src_sym.st_size;	\
	} while (0)

/* Both 32bit and 64bit use the same 1 byte field for type. (See elf.h) */
#define ELF_ST_TYPE(val) ELF32_ST_TYPE(val)

struct lttng_elf_ehdr {
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct lttng_elf_shdr {
	uint32_t sh_name;
	uint32_t sh_type;
	uint64_t sh_flags;
	uint64_t sh_addr;
	uint64_t sh_offset;
	uint64_t sh_size;
	uint32_t sh_link;
	uint32_t sh_info;
	uint64_t sh_addralign;
	uint64_t sh_entsize;
};

/*
 * This struct can hold both 32bit and 64bit symbol description. It's used with
 * the copy_sym() macro. Using this abstraction, we can use the same code for
 * both bitness.
 */
struct lttng_elf_sym {
	uint32_t st_name;
	uint8_t  st_info;
	uint8_t  st_other;
	uint16_t st_shndx;
	uint64_t st_value;
	uint64_t st_size;
};

struct lttng_elf {
	int fd;
	size_t file_size;
	uint8_t bitness;
	uint8_t endianness;
	/* Offset in bytes to start of section names string table. */
	off_t section_names_offset;
	/* Size in bytes of section names string table. */
	size_t section_names_size;
	struct lttng_elf_ehdr *ehdr;
};

static inline
int is_elf_32_bit(struct lttng_elf *elf)
{
	return elf->bitness == ELFCLASS32;
}

static inline
int is_elf_native_endian(struct lttng_elf *elf)
{
	return elf->endianness == NATIVE_ELF_ENDIANNESS;
}

static
int populate_section_header(struct lttng_elf * elf, struct lttng_elf_shdr *shdr,
		uint32_t index)
{
	int ret = 0;
	off_t offset;

	/* Compute the offset of the section in the file */
	offset = (off_t) elf->ehdr->e_shoff
			+ (off_t) index * elf->ehdr->e_shentsize;

	if (lseek(elf->fd, offset, SEEK_SET) < 0) {
		PERROR("Error seeking to the beginning of ELF section header");
		ret = -1;
		goto error;
	}

	if (is_elf_32_bit(elf)) {
		Elf32_Shdr elf_shdr;

		if (lttng_read(elf->fd, &elf_shdr, sizeof(elf_shdr)) < sizeof(elf_shdr)) {
			PERROR("Error reading ELF section header");
			ret = -1;
			goto error;
		}
		if (!is_elf_native_endian(elf)) {
			bswap_shdr(elf_shdr);
		}
		copy_shdr(elf_shdr, *shdr);
	} else {
		Elf64_Shdr elf_shdr;

		if (lttng_read(elf->fd, &elf_shdr, sizeof(elf_shdr)) < sizeof(elf_shdr)) {
			PERROR("Error reading ELF section header");
			ret = -1;
			goto error;
		}
		if (!is_elf_native_endian(elf)) {
			bswap_shdr(elf_shdr);
		}
		copy_shdr(elf_shdr, *shdr);
	}

error:
	return ret;
}

static
int populate_elf_header(struct lttng_elf *elf)
{
	int ret = 0;

	/*
	 * Move the read pointer back to the beginning to read the full header
	 * and copy it in our structure.
	 */
	if (lseek(elf->fd, 0, SEEK_SET) < 0) {
		PERROR("Error seeking to the beginning of the file");
		ret = -1;
		goto error;
	}

	/*
	 * Use macros to set fields in the ELF header struct for both 32bit and
	 * 64bit.
	 */
	if (is_elf_32_bit(elf)) {
		Elf32_Ehdr elf_ehdr;

		if (lttng_read(elf->fd, &elf_ehdr, sizeof(elf_ehdr)) < sizeof(elf_ehdr)) {
			ret = -1;
			goto error;
		}
		if (!is_elf_native_endian(elf)) {
			bswap_ehdr(elf_ehdr);
		}
		copy_ehdr(elf_ehdr, *(elf->ehdr));
	} else {
		Elf64_Ehdr elf_ehdr;

		if (lttng_read(elf->fd, &elf_ehdr, sizeof(elf_ehdr)) < sizeof(elf_ehdr)) {
			ret = -1;
			goto error;
		}
		if (!is_elf_native_endian(elf)) {
			bswap_ehdr(elf_ehdr);
		}
		copy_ehdr(elf_ehdr, *(elf->ehdr));
	}
error:
	return ret;
}

/*
 * Retrieve the nth (where n is the `index` argument) shdr (section
 * header) from the given elf instance.
 *
 * 0 is returned on succes, -1 on failure.
 */
static
int lttng_elf_get_section_hdr(struct lttng_elf *elf,
		uint16_t index, struct lttng_elf_shdr *out_header)
{
	int ret = 0;

	if (!elf) {
		ret = -1;
		goto error;
	}

	if (index >= elf->ehdr->e_shnum) {
		ret = -1;
		goto error;
	}

	ret = populate_section_header(elf, out_header, index);
	if (ret) {
		DBG("Error populating section header.");
		goto error;
	}

error:
	return ret;
}

/*
 * Lookup a section's name from a given offset (usually from an shdr's
 * sh_name value) in bytes relative to the beginning of the section
 * names string table.
 *
 * If no name is found, NULL is returned.
 */
static
char *lttng_elf_get_section_name(struct lttng_elf *elf, off_t offset)
{
	char *name = NULL;
	size_t name_length = 0, to_read;	/* name_length does not include \0 */

	if (!elf) {
		goto error;
	}

	if (offset >= elf->section_names_size) {
		goto error;
	}

	if (lseek(elf->fd, elf->section_names_offset + offset, SEEK_SET) < 0) {
		PERROR("Error seeking to the beginning of ELF string table section");
		goto error;
	}

	to_read = elf->section_names_size - offset;

	/* Find first \0 after or at current location, remember name_length. */
	for (;;) {
		char buf[BUF_LEN];
		ssize_t read_len;
		size_t i;

		if (!to_read) {
			goto error;
		}
		read_len = lttng_read(elf->fd, buf, min_t(size_t, BUF_LEN, to_read));
		if (read_len <= 0) {
			PERROR("Error reading ELF string table section");
			goto error;
		}
		for (i = 0; i < read_len; i++) {
			if (buf[i] == '\0') {
				name_length += i;
				goto end;
			}
		}
		name_length += read_len;
		to_read -= read_len;
	}
end:
	/*
	 * We found the length of the section name, now seek back to the
	 * beginning of the name and copy it in the newly allocated buffer.
	 */
	name = zmalloc(sizeof(char) * (name_length + 1));	/* + 1 for \0 */
	if (!name) {
		PERROR("Error allocating ELF section name buffer");
		goto error;
	}
	if (lseek(elf->fd, elf->section_names_offset + offset, SEEK_SET) < 0) {
		PERROR("Error seeking to the offset of the ELF section name");
		goto error;
	}
	if (lttng_read(elf->fd, name, name_length + 1) < name_length + 1) {
		PERROR("Error reading the ELF section name");
		goto error;
	}

	return name;

error:
	free(name);
	return NULL;
}

static
int lttng_elf_validate_and_populate(struct lttng_elf *elf)
{
	uint8_t version;
	uint8_t e_ident[EI_NIDENT];
	uint8_t *magic_number = NULL;
	int ret = 0;

	if (elf->fd == -1) {
		DBG("fd error");
		ret = LTTNG_ERR_ELF_PARSING;
		goto end;
	}

	/*
	 * First read the magic number, endianness and version to later populate
	 * the ELF header with the correct endianness and bitness.
	 * (see elf.h)
	 */

	if (lseek(elf->fd, 0, SEEK_SET) < 0) {
		PERROR("Error seeking the beginning of ELF file");
		ret = LTTNG_ERR_ELF_PARSING;
		goto end;
	}
	ret = lttng_read(elf->fd, e_ident, EI_NIDENT);
	if (ret < EI_NIDENT) {
		DBG("Error reading the ELF identification fields");
		if (ret == -1) {
			PERROR("Error reading the ELF identification fields");
		}
		ret = LTTNG_ERR_ELF_PARSING;
		goto end;
	}

	/*
	 * Copy fields used to check that the target file is in fact a valid ELF
	 * file.
	 */
	elf->bitness = e_ident[EI_CLASS];
	elf->endianness = e_ident[EI_DATA];
	version = e_ident[EI_VERSION];
	magic_number = &e_ident[EI_MAG0];

	/*
	 * Check the magic number.
	 */
	if (memcmp(magic_number, ELFMAG, SELFMAG) != 0) {
		DBG("Error check ELF magic number.");
		ret = LTTNG_ERR_ELF_PARSING;
		goto end;
	}

	/*
	 * Check the bitness is either ELFCLASS32 or ELFCLASS64.
	 */
	if (elf->bitness <= ELFCLASSNONE || elf->bitness >= ELFCLASSNUM) {
		DBG("ELF class error.");
		ret = LTTNG_ERR_ELF_PARSING;
		goto end;
	}

	/*
	 * Check the endianness is either ELFDATA2LSB or ELFDATA2MSB.
	 */
	if (elf->endianness <= ELFDATANONE || elf->endianness >= ELFDATANUM) {
		DBG("ELF endianness error.");
		ret = LTTNG_ERR_ELF_PARSING;
		goto end;
	}

	/*
	 * Check the version is ELF_CURRENT.
	 */
	if (version <= EV_NONE || version >= EV_NUM) {
		DBG("Wrong ELF version.");
		ret = LTTNG_ERR_ELF_PARSING;
		goto end;
	}

	elf->ehdr = zmalloc(sizeof(struct lttng_elf_ehdr));
	if (!elf->ehdr) {
		PERROR("Error allocation buffer for ELF header");
		ret = LTTNG_ERR_NOMEM;
		goto end;
	}

	/*
	 * Copy the content of the elf header.
	 */
	ret = populate_elf_header(elf);
	if (ret) {
		DBG("Error reading ELF header,");
		goto free_elf_error;
	}

	goto end;

free_elf_error:
	free(elf->ehdr);
	elf->ehdr = NULL;
end:
	return ret;
}

/*
 * Create an instance of lttng_elf for the ELF file located at
 * `path`.
 *
 * Return a pointer to the instance on success, NULL on failure.
 */
static
struct lttng_elf *lttng_elf_create(int fd)
{
	struct lttng_elf_shdr section_names_shdr;
	struct lttng_elf *elf = NULL;
	int ret;
	struct stat stat_buf;

	if (fd < 0) {
		goto error;
	}

	ret = fstat(fd, &stat_buf);
	if (ret) {
		PERROR("Failed to determine size of elf file");
		goto error;
	}
	if (!S_ISREG(stat_buf.st_mode)) {
		ERR("Refusing to initialize lttng_elf from non-regular file");
		goto error;
	}

	elf = zmalloc(sizeof(struct lttng_elf));
	if (!elf) {
		PERROR("Error allocating struct lttng_elf");
		goto error;
	}
	elf->file_size = (size_t) stat_buf.st_size;

	elf->fd = dup(fd);
	if (elf->fd < 0) {
		PERROR("Error duplicating file descriptor to binary");
		goto error;
	}

	ret = lttng_elf_validate_and_populate(elf);
	if (ret) {
		goto error;
	}

	ret = lttng_elf_get_section_hdr(
			elf, elf->ehdr->e_shstrndx, &section_names_shdr);
	if (ret) {
		goto error;
	}

	elf->section_names_offset = section_names_shdr.sh_offset;
	elf->section_names_size = section_names_shdr.sh_size;
	return elf;

error:
	if (elf) {
		if (elf->ehdr) {
			free(elf->ehdr);
		}
		if (elf->fd >= 0) {
			if (close(elf->fd)) {
				PERROR("Error closing file descriptor in error path");
				abort();
			}
		}
		free(elf);
	}
	return NULL;
}

/*
 * Destroy the given lttng_elf instance.
 */
static
void lttng_elf_destroy(struct lttng_elf *elf)
{
	if (!elf) {
		return;
	}

	free(elf->ehdr);
	if (close(elf->fd)) {
		PERROR("Error closing file description in error path");
		abort();
	}
	free(elf);
}

static
int lttng_elf_get_section_hdr_by_name(struct lttng_elf *elf,
		const char *section_name, struct lttng_elf_shdr *section_hdr)
{
	int i;
	char *curr_section_name;

	for (i = 0; i < elf->ehdr->e_shnum; ++i) {
		bool name_equal;
	        int ret = lttng_elf_get_section_hdr(elf, i, section_hdr);

		if (ret) {
			break;
		}
		curr_section_name = lttng_elf_get_section_name(elf,
				section_hdr->sh_name);
		if (!curr_section_name) {
			continue;
		}
		name_equal = strcmp(curr_section_name, section_name) == 0;
		free(curr_section_name);
		if (name_equal) {
			return 0;
		}
	}
	return LTTNG_ERR_ELF_PARSING;
}

static
char *lttng_elf_get_section_data(struct lttng_elf *elf,
		struct lttng_elf_shdr *shdr)
{
	int ret;
	off_t section_offset;
	char *data;
	size_t max_alloc_size;

	if (!elf || !shdr) {
		goto error;
	}

	max_alloc_size = min_t(size_t, MAX_SECTION_DATA_SIZE, elf->file_size);

	section_offset = shdr->sh_offset;
	if (lseek(elf->fd, section_offset, SEEK_SET) < 0) {
		PERROR("Error seeking to section offset");
		goto error;
	}

	if (shdr->sh_size > max_alloc_size) {
		ERR("ELF section size exceeds maximal allowed size of %zu bytes",
				max_alloc_size);
		goto error;
	}
	data = zmalloc(shdr->sh_size);
	if (!data) {
		PERROR("Error allocating buffer for ELF section data");
		goto error;
	}
	ret = lttng_read(elf->fd, data, shdr->sh_size);
	if (ret == -1) {
		PERROR("Error reading ELF section data");
		goto free_error;
	}

	return data;

free_error:
	free(data);
error:
	return NULL;
}

/*
 * Convert the virtual address in a binary's mapping to the offset of
 * the corresponding instruction in the binary file.
 * This function assumes the address is in the text section.
 *
 * Returns the offset on success or non-zero in case of failure.
 */
static
int lttng_elf_convert_addr_in_text_to_offset(struct lttng_elf *elf_handle,
		size_t addr, uint64_t *offset)
{
	int ret = 0;
	off_t text_section_offset;
	off_t text_section_addr_beg;
	off_t text_section_addr_end;
	off_t offset_in_section;
	struct lttng_elf_shdr text_section_hdr;

	if (!elf_handle) {
		DBG("Invalid ELF handle.");
		ret = LTTNG_ERR_ELF_PARSING;
		goto error;
	}

	/* Get a pointer to the .text section header. */
	ret = lttng_elf_get_section_hdr_by_name(elf_handle,
			TEXT_SECTION_NAME, &text_section_hdr);
	if (ret) {
		DBG("Text section not found in binary.");
		ret = LTTNG_ERR_ELF_PARSING;
		goto error;
	}

	text_section_offset = text_section_hdr.sh_offset;
	text_section_addr_beg = text_section_hdr.sh_addr;
	text_section_addr_end =
			text_section_addr_beg + text_section_hdr.sh_size;

	/*
	 * Verify that the address is within the .text section boundaries.
	 */
	if (addr < text_section_addr_beg || addr > text_section_addr_end) {
		DBG("Address found is outside of the .text section addr=0x%zx, "
			".text section=[0x%jd - 0x%jd].", addr, (intmax_t)text_section_addr_beg,
			(intmax_t)text_section_addr_end);
		ret = LTTNG_ERR_ELF_PARSING;
		goto error;
	}

	offset_in_section = addr - text_section_addr_beg;

	/*
	 * Add the target offset in the text section to the offset of this text
	 * section from the beginning of the binary file.
	 */
	*offset = text_section_offset + offset_in_section;

error:
	return ret;
}

/*
 * Compute the offset of a symbol from the begining of the ELF binary.
 *
 * On success, returns 0 offset parameter is set to the computed value
 * On failure, returns -1.
 */
int lttng_elf_get_symbol_offset(int fd, char *symbol, uint64_t *offset)
{
	int ret = 0;
	int sym_found = 0;
	int sym_count = 0;
	int sym_idx = 0;
	uint64_t addr = 0;
	char *curr_sym_str = NULL;
	char *symbol_table_data = NULL;
	char *string_table_data = NULL;
	const char *string_table_name = NULL;
	struct lttng_elf_shdr symtab_hdr;
	struct lttng_elf_shdr strtab_hdr;
	struct lttng_elf *elf = NULL;

	if (!symbol || !offset ) {
		ret = LTTNG_ERR_ELF_PARSING;
		goto end;
	}

	elf = lttng_elf_create(fd);
	if (!elf) {
		ret = LTTNG_ERR_ELF_PARSING;
		goto end;
	}

	/*
	 * The .symtab section might not exist on stripped binaries.
	 * Try to get the symbol table section header first. If it's absent,
	 * try to get the dynamic symbol table. All symbols in the dynamic
	 * symbol tab are in the (normal) symbol table if it exists.
	 */
	ret = lttng_elf_get_section_hdr_by_name(elf, SYMBOL_TAB_SECTION_NAME,
			&symtab_hdr);
	if (ret) {
		DBG("Cannot get ELF Symbol Table section. Trying to get ELF Dynamic Symbol Table section.");
		/* Get the dynamic symbol table section header. */
		ret = lttng_elf_get_section_hdr_by_name(elf, DYNAMIC_SYMBOL_TAB_SECTION_NAME,
				&symtab_hdr);
		if (ret) {
			DBG("Cannot get ELF Symbol Table nor Dynamic Symbol Table sections.");
			ret = LTTNG_ERR_ELF_PARSING;
			goto destroy_elf;
		}
		string_table_name = DYNAMIC_STRING_TAB_SECTION_NAME;
	} else {
		string_table_name = STRING_TAB_SECTION_NAME;
	}

	/* Get the data associated with the symbol table section. */
	symbol_table_data = lttng_elf_get_section_data(elf, &symtab_hdr);
	if (symbol_table_data == NULL) {
		DBG("Cannot get ELF Symbol Table data.");
		ret = LTTNG_ERR_ELF_PARSING;
		goto destroy_elf;
	}

	/* Get the string table section header. */
	ret = lttng_elf_get_section_hdr_by_name(elf, string_table_name,
			&strtab_hdr);
	if (ret) {
		DBG("Cannot get ELF string table section.");
		goto free_symbol_table_data;
	}

	/* Get the data associated with the string table section. */
	string_table_data = lttng_elf_get_section_data(elf, &strtab_hdr);
	if (string_table_data == NULL) {
		DBG("Cannot get ELF string table section data.");
		ret = LTTNG_ERR_ELF_PARSING;
		goto free_symbol_table_data;
	}

	/* Get the number of symbol in the table for the iteration. */
	sym_count = symtab_hdr.sh_size / symtab_hdr.sh_entsize;

	/* Loop over all symbol. */
	for (sym_idx = 0; sym_idx < sym_count; sym_idx++) {
		struct lttng_elf_sym curr_sym;

		/* Get the symbol at the current index. */
		if (is_elf_32_bit(elf)) {
			Elf32_Sym tmp = ((Elf32_Sym *) symbol_table_data)[sym_idx];
			copy_sym(tmp, curr_sym);
		} else {
			Elf64_Sym tmp = ((Elf64_Sym *) symbol_table_data)[sym_idx];
			copy_sym(tmp, curr_sym);
		}

		/*
		 * If the st_name field is zero, there is no string name for
		 * this symbol; skip to the next symbol.
		 */
		if (curr_sym.st_name == 0) {
			continue;
		}

		/*
		 * Use the st_name field in the lttng_elf_sym struct to get offset of
		 * the symbol's name from the beginning of the string table.
		 */
		curr_sym_str = string_table_data + curr_sym.st_name;

		/*
		 * If the current symbol is not a function; skip to the next symbol.
		 */
		if (ELF_ST_TYPE(curr_sym.st_info) != STT_FUNC) {
			continue;
		}

		/*
		 * Compare with the search symbol. If there is a match set the address
		 * output parameter and return success.
		 */
		if (strcmp(symbol, curr_sym_str) == 0 ) {
			sym_found = 1;
			addr = curr_sym.st_value;
			break;
		}
	}

	if (!sym_found) {
		DBG("Symbol not found.");
		ret = LTTNG_ERR_ELF_PARSING;
		goto free_string_table_data;
	}

	/*
	 * Use the virtual address of the symbol to compute the offset of this
	 * symbol from the beginning of the executable file.
	 */
	ret = lttng_elf_convert_addr_in_text_to_offset(elf, addr, offset);
	if (ret) {
		DBG("Cannot convert addr to offset.");
		goto free_string_table_data;
	}


free_string_table_data:
	free(string_table_data);
free_symbol_table_data:
	free(symbol_table_data);
destroy_elf:
	lttng_elf_destroy(elf);
end:
	return ret;
}

/*
 * Compute the offsets of SDT probes from the begining of the ELF binary.
 *
 * On success, returns 0 and the nb_probes parameter is set to the number of
 * offsets found and the offsets parameter points to an array of offsets where
 * the SDT probes are.
 * On failure, returns -1.
 */
int lttng_elf_get_sdt_probe_offsets(int fd, const char *provider_name,
		const char *probe_name, uint64_t **offsets, uint32_t *nb_probes)
{
	int ret = 0, nb_match = 0;
	struct lttng_elf_shdr stap_note_section_hdr;
	struct lttng_elf *elf = NULL;
	char *stap_note_section_data = NULL;
	char *curr_note_section_begin, *curr_data_ptr, *curr_probe, *curr_provider;
	char *next_note_ptr;
	uint32_t name_size, desc_size, note_type;
	uint64_t curr_probe_location, curr_probe_offset, curr_semaphore_location;
	uint64_t *probe_locs = NULL, *new_probe_locs = NULL;

	if (!provider_name || !probe_name || !nb_probes || !offsets) {
		DBG("Invalid arguments.");
		ret = LTTNG_ERR_ELF_PARSING;
		goto error;
	}

	elf = lttng_elf_create(fd);
	if (!elf) {
		DBG("Error allocation ELF.");
		ret = LTTNG_ERR_ELF_PARSING;
		goto error;
	}

	/* Get the stap note section header. */
	ret = lttng_elf_get_section_hdr_by_name(elf, NOTE_STAPSDT_SECTION_NAME,
			&stap_note_section_hdr);
	if (ret) {
		DBG("Cannot get ELF stap note section.");
		goto destroy_elf_error;
	}

	/* Get the data associated with the stap note section. */
	stap_note_section_data =
			lttng_elf_get_section_data(elf, &stap_note_section_hdr);
	if (stap_note_section_data == NULL) {
		DBG("Cannot get ELF stap note section data.");
		ret = LTTNG_ERR_ELF_PARSING;
		goto destroy_elf_error;
	}

	next_note_ptr = stap_note_section_data;
	curr_note_section_begin = stap_note_section_data;

	*offsets = NULL;
	while (1) {
		curr_data_ptr = next_note_ptr;
		/* Check if we have reached the end of the note section. */
		if (curr_data_ptr >=
				curr_note_section_begin +
						stap_note_section_hdr.sh_size) {
			*nb_probes = nb_match;
			*offsets = probe_locs;
			ret = 0;
			break;
		}
		/* Get name size field. */
		name_size = next_4bytes_boundary(*(uint32_t*) curr_data_ptr);
		curr_data_ptr += sizeof(uint32_t);

		/* Sanity check; a zero name_size is reserved. */
		if (name_size == 0) {
			DBG("Invalid name size field in SDT probe descriptions"
				"section.");
			ret = -1;
			goto realloc_error;
		}

		/* Get description size field. */
		desc_size = next_4bytes_boundary(*(uint32_t*) curr_data_ptr);
		curr_data_ptr += sizeof(uint32_t);

		/* Get type field. */
		note_type = *(uint32_t *) curr_data_ptr;
		curr_data_ptr += sizeof(uint32_t);

		/*
		 * Move the pointer to the next note to be ready for the next
		 * iteration. The current note is made of 3 unsigned 32bit
		 * integers (name size, descriptor size and note type), the
		 * name and the descriptor. To move to the next note, we move
		 * the pointer according to those values.
		 */
		next_note_ptr = next_note_ptr +
			(3 * sizeof(uint32_t)) + desc_size + name_size;

		/*
		 * Move ptr to the end of the name string (we don't need it)
		 * and go to the next 4 byte alignement.
		 */
		if (note_type != NOTE_STAPSDT_TYPE ||
			strncmp(curr_data_ptr, NOTE_STAPSDT_NAME, name_size) != 0) {
			continue;
		}

		curr_data_ptr += name_size;

		/* Get probe location.  */
		curr_probe_location = *(uint64_t *) curr_data_ptr;
		curr_data_ptr += sizeof(uint64_t);

		/* Pass over the base. Not needed. */
		curr_data_ptr += sizeof(uint64_t);

		/* Get semaphore location. */
		curr_semaphore_location = *(uint64_t *) curr_data_ptr;
		curr_data_ptr += sizeof(uint64_t);
		/* Get provider name. */
		curr_provider = curr_data_ptr;
		curr_data_ptr += strlen(curr_provider) + 1;

		/* Get probe name. */
		curr_probe = curr_data_ptr;

		/* Check if the provider and probe name match */
		if (strcmp(provider_name, curr_provider) == 0 &&
				strcmp(probe_name, curr_probe) == 0) {
			int new_size;

			/*
			 * We currently don't support SDT probes with semaphores. Return
			 * success as we found a matching probe but it's guarded by a
			 * semaphore.
			 */
			if (curr_semaphore_location != 0) {
				ret = LTTNG_ERR_SDT_PROBE_SEMAPHORE;
				goto realloc_error;
			}

			new_size = (++nb_match) * sizeof(uint64_t);

			/*
			 * Found a match with not semaphore, we need to copy the
			 * probe_location to the output parameter.
			 */
			new_probe_locs = realloc(probe_locs, new_size);
			if (!new_probe_locs) {
				/* Error allocating a larger buffer */
				DBG("Allocation error in SDT.");
				ret = LTTNG_ERR_NOMEM;
				goto realloc_error;
			}
			probe_locs = new_probe_locs;
			new_probe_locs = NULL;

			/*
			 * Use the virtual address of the probe to compute the offset of
			 * this probe from the beginning of the executable file.
			 */
			ret = lttng_elf_convert_addr_in_text_to_offset(elf,
					curr_probe_location, &curr_probe_offset);
			if (ret) {
				DBG("Conversion error in SDT.");
				goto realloc_error;
			}

			probe_locs[nb_match - 1] = curr_probe_offset;
		}
	}

end:
	free(stap_note_section_data);
destroy_elf_error:
	lttng_elf_destroy(elf);
error:
	return ret;
realloc_error:
	free(probe_locs);
	goto end;
}
