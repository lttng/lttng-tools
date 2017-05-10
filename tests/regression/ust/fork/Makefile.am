AM_CPPFLAGS += -I$(srcdir)

noinst_PROGRAMS = fork fork2
fork_SOURCES = fork.c ust_tests_fork.h
fork_LDADD = -llttng-ust -llttng-ust-fork $(DL_LIBS)

fork2_SOURCES = fork2.c
fork2_LDADD = -llttng-ust -llttng-ust-fork $(DL_LIBS)

noinst_SCRIPTS = test_fork test_fork.py
EXTRA_DIST = test_fork test_fork.py

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
