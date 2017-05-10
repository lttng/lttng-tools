AM_CPPFLAGS += -I$(top_srcdir)/tests -I$(srcdir)

if HAVE_LIBLTTNG_UST_CTL
noinst_PROGRAMS = gen-ust-events
gen_ust_events_SOURCES = gen-ust-events.c tp.c tp.h
gen_ust_events_LDADD = -llttng-ust -lurcu-bp $(DL_LIBS)
endif

noinst_SCRIPTS = test_unsupported_op test_invalid_filter test_valid_filter
EXTRA_DIST = test_unsupported_op test_invalid_filter test_valid_filter

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
