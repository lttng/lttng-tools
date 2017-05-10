# -Wsystem-headers is needed to print warnings in the tracepoint
# description file.
AM_CPPFLAGS += -I$(srcdir) -Wsystem-headers

# Set LIBS to nothing so the application does not link on useless
# libraries.
LIBS =

# Build a version of the test app with built-in tracepoints
demo_builtin_SOURCES = demo.c tp.c tp2.c tp3.c ust_tests_demo.h \
	ust_tests_demo2.h ust_tests_demo3.h
demo_builtin_LDADD = -llttng-ust $(DL_LIBS)
demo_builtin_CFLAGS = -Werror=old-style-definition $(AM_CFLAGS)

# Build a version statically linked to the providers
# contains ust_tests_demo.h and ust_tests_demo2.h provider probes
noinst_LTLIBRARIES = liblttng-ust-provider-ust-tests-demo-static.la \
	liblttng-ust-provider-ust-tests-demo3-static.la

liblttng_ust_provider_ust_tests_demo_static_la_SOURCES = \
	tp.c ust_tests_demo.h \
	tp2.c ust_tests_demo2.h
liblttng_ust_provider_ust_tests_demo_static_la_LIBADD = \
	-llttng-ust

# contains ust_tests_demo3.h provider probes
liblttng_ust_provider_ust_tests_demo3_static_la_SOURCES = \
	tp3.c ust_tests_demo3.h
liblttng_ust_provider_ust_tests_demo3_static_la_LIBADD = \
	-llttng-ust

demo_static_SOURCES = demo.c
demo_static_LDADD = liblttng-ust-provider-ust-tests-demo-static.la \
	liblttng-ust-provider-ust-tests-demo3-static.la \
	$(DL_LIBS)

noinst_PROGRAMS = demo_builtin demo_static

COPYSCRIPTS = test_linking test_linking.py demo_preload
noinst_SCRIPTS = $(COPYSCRIPTS)

if NO_SHARED

EXTRA_DIST = tp.c ust_tests_demo.h tp2.c ust_tests_demo2.h \
	tp3.c ust_tests_demo3.h demo.c ust_tests_demo.h \
	$(COPYSCRIPTS)

else
# Force the shared flag on the noinst libraries since they are
# only built static by default
FORCE_SHARED_LIB_OPTIONS = -module -shared -avoid-version \
			   -rpath $(abs_builddir)

noinst_LTLIBRARIES += liblttng-ust-provider-ust-tests-demo.la \
	liblttng-ust-provider-ust-tests-demo3.la

#contains ust_tests_demo.h and ust_tests_demo2.h provider probes
liblttng_ust_provider_ust_tests_demo_la_SOURCES = \
	tp.c ust_tests_demo.h \
	tp2.c ust_tests_demo2.h
liblttng_ust_provider_ust_tests_demo_la_LIBADD = -llttng-ust
liblttng_ust_provider_ust_tests_demo_la_LDFLAGS = \
	$(FORCE_SHARED_LIB_OPTIONS)

#contains ust_tests_demo3.h provider probes
liblttng_ust_provider_ust_tests_demo3_la_SOURCES = \
	tp3.c ust_tests_demo3.h
liblttng_ust_provider_ust_tests_demo3_la_LIBADD = -llttng-ust
liblttng_ust_provider_ust_tests_demo3_la_LDFLAGS = \
	$(FORCE_SHARED_LIB_OPTIONS)

noinst_PROGRAMS += demo
demo_SOURCES = demo.c ust_tests_demo.h
demo_CFLAGS = -DTEST_DYNAMIC_LINKAGE $(AM_CFLAGS)
demo_LDADD = $(DL_LIBS)

EXTRA_DIST = $(COPYSCRIPTS)

endif

all-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(COPYSCRIPTS); do \
			cp -f $(srcdir)/$$script $(builddir); \
		done; \
	fi

clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(COPYSCRIPTS); do \
			rm -f $(builddir)/$$script; \
		done; \
	fi
