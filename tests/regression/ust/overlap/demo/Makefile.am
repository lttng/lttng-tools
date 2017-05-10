if NO_SHARED
# Do not build this test if shared libraries support was
# explicitly disabled.

CLEANFILES = demo

EXTRA_DIST = demo-trace demo.c ust_tests_demo.h \
	tp3.c ust_tests_demo3.h tp2.c ust_tests_demo2.h \
	tp.c ust_tests_demo.h

else

AM_CPPFLAGS += -I$(srcdir)

# Force the shared flag on the noinst libraries since they are
# only built static by default
FORCE_SHARED_LIB_OPTIONS = -module -shared -avoid-version \
						   -rpath $(abs_builddir)

#contains ust_tests_demo.h and ust_tests_demo2.h provider probes
liblttng_ust_provider_ust_tests_demo_la_SOURCES = \
	tp.c ust_tests_demo.h \
	tp2.c ust_tests_demo2.h
liblttng_ust_provider_ust_tests_demo_la_LIBADD = -llttng-ust
liblttng_ust_provider_ust_tests_demo_la_LDFLAGS = $(FORCE_SHARED_LIB_OPTIONS)

#contains ust_tests_demo3.h provider probes
liblttng_ust_provider_ust_tests_demo3_la_SOURCES = tp3.c ust_tests_demo3.h
liblttng_ust_provider_ust_tests_demo3_la_LIBADD = -llttng-ust
liblttng_ust_provider_ust_tests_demo3_la_LDFLAGS = $(FORCE_SHARED_LIB_OPTIONS)

noinst_LTLIBRARIES = liblttng-ust-provider-ust-tests-demo.la \
					 liblttng-ust-provider-ust-tests-demo3.la

noinst_PROGRAMS = demo
demo_SOURCES = demo.c ust_tests_demo.h
# The demo program only depends on libdl/libc for dlopen().
demo_LDADD = $(DL_LIBS)

noinst_SCRIPTS = demo-trace
EXTRA_DIST = demo-trace

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
