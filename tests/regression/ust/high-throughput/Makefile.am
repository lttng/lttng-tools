AM_CPPFLAGS += -I$(srcdir)

if LTTNG_TOOLS_BUILD_WITH_LIBDL
LIBS += -ldl
endif
if LTTNG_TOOLS_BUILD_WITH_LIBC_DL
LIBS += -lc
endif

noinst_PROGRAMS = gen-events
gen_events_SOURCES = main.c tp.c tp.h
gen_events_LDADD = -llttng-ust

noinst_SCRIPTS = test_high_throughput
EXTRA_DIST = test_high_throughput

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
