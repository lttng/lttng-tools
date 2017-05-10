if NO_SHARED
# Do not build this test if shared libraries support was
# explicitly disabled.

CLEANFILES = lttng-ust-getcpu-override-test.so \
	lttng-ust-getcpu-override-test.so.debug

EXTRA_DIST = test_getcpu_override run-getcpu-override \
	lttng-ust-getcpu-override-test.c

else

# The rpath is necessary because libtool won't build a shared library
# if it's noinst_
GETCPU_LIBTOOL_FLAGS = \
    -module \
    -shared \
    -avoid-version \
    --no-as-needed \
    -rpath $(abs_builddir)

noinst_LTLIBRARIES = lttng-ust-getcpu-override-test.la
lttng_ust_getcpu_override_test_la_LDFLAGS = $(GETCPU_LIBTOOL_FLAGS)
lttng_ust_getcpu_override_test_la_SOURCES = lttng-ust-getcpu-override-test.c
lttng_ust_getcpu_override_test_la_LIBADD = $(DL_LIBS)

noinst_SCRIPTS = test_getcpu_override run-getcpu-override
EXTRA_DIST = test_getcpu_override run-getcpu-override

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
