AM_CPPFLAGS = -I$(srcdir)

noinst_PROGRAMS = prog
prog_SOURCES = prog.c
prog_LDADD = -llttng-ust -llttng-ust-libc-wrapper

noinst_SCRIPTS = test_libc-wrapper test_libc-wrapper.py
EXTRA_DIST = test_libc-wrapper test_libc-wrapper.py
