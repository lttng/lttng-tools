AM_CPPFLAGS += -I$(srcdir)

noinst_PROGRAMS = daemon
daemon_SOURCES = daemon.c ust_tests_daemon.h
daemon_LDADD = -llttng-ust -llttng-ust-fork $(DL_LIBS)

noinst_SCRIPTS = test_daemon test_daemon.py
EXTRA_DIST = test_daemon test_daemon.py

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
