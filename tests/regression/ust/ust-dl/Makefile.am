if NO_SHARED
# Do not build this test if shared libraries support was
# explicitly disabled.

CLEANFILES = libbar.so libbar.so.debug libfoo.so libfoo.so.debug \
	libzzz.so libzzz.so.debug prog libtp.so

EXTRA_DIST = test_ust-dl test_ust-dl.py libbar.c libbar.h libbar-tp.h \
	libbar-tp.c libfoo.c libfoo.h libfoo-tp.h libfoo-tp.c \
	libzzz.c libzzz.h libzzz-tp.h libzzz-tp.c prog.c libtp.c

else

objcopy_verbose = $(objcopy_verbose_@AM_V@)
objcopy_verbose_ = $(objcopy_verbose_@AM_DEFAULT_V@)
objcopy_verbose_0 = @echo "  OBJCOPY " $@;

AM_CPPFLAGS += -I$(srcdir) -g

noinst_PROGRAMS = prog
prog_SOURCES = prog.c
prog_LDADD = -ldl

noinst_LTLIBRARIES = libzzz.la libbar.la libfoo.la libtp.la

libzzz_la_SOURCES = libzzz.c libzzz.h
libzzz_la_LDFLAGS = -module -shared -avoid-version \
		-rpath $(abs_builddir)

libbar_la_SOURCES = libbar.c libbar.h
libbar_la_LDFLAGS = -module -shared -avoid-version \
		-rpath $(abs_builddir)
libbar_la_LIBADD = libzzz.la

libfoo_la_SOURCES = libfoo.c libfoo.h
libfoo_la_LDFLAGS = -module -shared -avoid-version \
		-rpath $(abs_builddir)
libfoo_la_LIBADD = libbar.la

CLEANFILES = libfoo.so libfoo.so.debug libbar.so libbar.so.debug \
	libzzz.so libzzz.so.debug libtp.so

libtp_la_SOURCES = libbar-tp.h libbar-tp.c libfoo-tp.h libfoo-tp.c \
	libzzz-tp.h libzzz-tp.c
libtp_la_LDFLAGS = -module -shared -rpath $(abs_builddir)

# Extract debug symbols
libfoo.so.debug: libfoo.la
	$(objcopy_verbose)$(OBJCOPY) --only-keep-debug .libs/libfoo.so libfoo.so.debug
libbar.so.debug: libbar.la
	$(objcopy_verbose)$(OBJCOPY) --only-keep-debug .libs/libbar.so libbar.so.debug
libzzz.so.debug: libzzz.la
	$(objcopy_verbose)$(OBJCOPY) --only-keep-debug .libs/libzzz.so libzzz.so.debug

# Strip and add debuglink
libfoo.so: libfoo.so.debug
	@cp -f .libs/libfoo.so libfoo.so
	$(objcopy_verbose)$(OBJCOPY) --strip-debug --add-gnu-debuglink=libfoo.so.debug libfoo.so
libbar.so: libbar.so.debug
	@cp -f .libs/libbar.so libbar.so
	$(objcopy_verbose)$(OBJCOPY) --strip-debug --add-gnu-debuglink=libbar.so.debug libbar.so
libzzz.so: libzzz.so.debug
	@cp -f .libs/libzzz.so libzzz.so
	$(objcopy_verbose)$(OBJCOPY) --strip-debug --add-gnu-debuglink=libzzz.so.debug libzzz.so

libtp.so: libtp.la
	@cp -f .libs/libtp.so libtp.so

noinst_SCRIPTS = test_ust-dl test_ust-dl.py
EXTRA_DIST = test_ust-dl test_ust-dl.py

all-local: libfoo.so libbar.so libzzz.so libtp.so
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

endif
