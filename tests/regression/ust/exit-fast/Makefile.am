AM_CPPFLAGS += -I$(srcdir)

noinst_PROGRAMS = exit-fast
exit_fast_SOURCES = exit-fast.c ust_tests_exitfast.h
exit_fast_LDADD = -llttng-ust

if LTTNG_TOOLS_BUILD_WITH_LIBDL
exit_fast_LDADD += -ldl
endif
if LTTNG_TOOLS_BUILD_WITH_LIBC_DL
exit_fast_LDADD += -lc
endif

noinst_SCRIPTS = test_exit-fast test_exit-fast.py
EXTRA_DIST = test_exit-fast test_exit-fast.py

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
