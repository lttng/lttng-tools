objcopy_verbose = $(objcopy_verbose_@AM_V@)
objcopy_verbose_ = $(objcopy_verbose_@AM_DEFAULT_V@)
objcopy_verbose_0 = @echo OBJCOPY $@;

AM_CPPFLAGS = -I$(srcdir) -g

noinst_PROGRAMS = prog
prog_SOURCES = prog.c
prog_LDADD = -ldl

noinst_LTLIBRARIES = libfoo.la
libfoo_la_SOURCES = libfoo.c libfoo.h
libfoo_la_LDFLAGS = -module -shared -avoid-version \
		-rpath $(abs_builddir)

noinst_SCRIPTS = test_ust-dl test_ust-dl.py
EXTRA_DIST = test_ust-dl test_ust-dl.py

# Extract debug symbols
libfoo.so.debug: libfoo.la
	$(objcopy_verbose)$(OBJCOPY) --only-keep-debug .libs/libfoo.so libfoo.so.debug

# Strip and add debuglink
libfoo.so: libfoo.so.debug
	@cp -f .libs/libfoo.so libfoo.so
	$(objcopy_verbose)$(OBJCOPY) --strip-debug --add-gnu-debuglink=libfoo.so.debug libfoo.so

all-local: libfoo.so
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			cp -f $(srcdir)/$$script $(builddir); \
		done; \
	fi

clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			rm -f $(builddir)/$$script; \
		done; \
	fi

CLEANFILES = libfoo.so libfoo.so.debug
