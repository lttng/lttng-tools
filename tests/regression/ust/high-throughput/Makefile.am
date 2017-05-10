AM_CPPFLAGS += -I$(srcdir)

noinst_PROGRAMS = gen-events
gen_events_SOURCES = main.c tp.c tp.h
gen_events_LDADD = -llttng-ust $(DL_LIBS)

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
