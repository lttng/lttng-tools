# SPDX-License-Identifier: GPL-2.0-only

# no optimization
AM_CFLAGS += -O0
noinst_LTLIBRARIES = libfoo.la

libfoo_la_SOURCES = foo.c foo.h
libfoo_la_LDFLAGS = -shared -module -avoid-version -rpath $(abs_builddir)/.libs/

noinst_PROGRAMS = userspace-probe-elf-binary
userspace_probe_elf_binary_SOURCES = userspace-probe-elf-binary.c
userspace_probe_elf_binary_LDADD = libfoo.la

libfoo.strip: libfoo.la
	$(OBJCOPY) --strip-all .libs/libfoo.so

all-local: libfoo.strip
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			cp -f $(srcdir)/$$script $(builddir); \
		done; \
	fi
