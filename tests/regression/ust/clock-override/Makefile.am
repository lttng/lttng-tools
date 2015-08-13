AM_CPPFLAGS = -I$(srcdir)

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
