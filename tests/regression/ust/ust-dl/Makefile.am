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

all-local: libfoo.la
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			cp -f $(srcdir)/$$script $(builddir); \
		done; \
	fi
	objcopy --only-keep-debug .libs/libfoo.so .libs/libfoo.so.debug
	strip -g .libs/libfoo.so
	objcopy --add-gnu-debuglink .libs/libfoo.so.debug .libs/libfoo.so

clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			rm -f $(builddir)/$$script; \
		done; \
	fi
	rm -f .libs/libfoo.so.debug
