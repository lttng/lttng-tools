if NO_SHARED
# Do not build this test if shared libraries support was
# explicitly disabled.

CLEANFILES = lttng-ust-clock-override-test.so \
	lttng-ust-clock-override-test.so.debug

EXTRA_DIST = test_clock_override lttng-ust-clock-override-test.c

else

AM_CPPFLAGS = -I$(srcdir) -I$(top_srcdir)/src

# The rpath is necessary because libtool won't build a shared library
# if it's noinst_
GETCPU_LIBTOOL_FLAGS = \
    -module \
    -shared \
    -avoid-version \
    --no-as-needed \
    -rpath $(abs_builddir)

noinst_LTLIBRARIES = lttng-ust-clock-override-test.la
lttng_ust_clock_override_test_la_LDFLAGS = $(GETCPU_LIBTOOL_FLAGS)
lttng_ust_clock_override_test_la_SOURCES = lttng-ust-clock-override-test.c

if LTTNG_TOOLS_BUILD_WITH_LIBDL
lttng_ust_clock_override_test_la_LIBADD = -ldl
endif
if LTTNG_TOOLS_BUILD_WITH_LIBC_DL
lttng_ust_clock_override_test_la_LIBADD = -lc
endif

noinst_SCRIPTS = test_clock_override
EXTRA_DIST = test_clock_override

all-local:
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
