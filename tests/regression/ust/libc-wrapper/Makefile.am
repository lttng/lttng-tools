noinst_PROGRAMS = prog
prog_SOURCES = prog.c
prog_LDADD = -llttng-ust -llttng-ust-libc-wrapper

noinst_SCRIPTS = test_libc-wrapper test_libc-wrapper.py
EXTRA_DIST = test_libc-wrapper test_libc-wrapper.py

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
