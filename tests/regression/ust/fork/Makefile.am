AM_CPPFLAGS = -I$(srcdir)

noinst_PROGRAMS = fork fork2
fork_SOURCES = fork.c ust_tests_fork.h
fork_LDADD = -llttng-ust -llttng-ust-fork

fork2_SOURCES = fork2.c
fork2_LDADD = -llttng-ust -llttng-ust-fork

if LTTNG_TOOLS_BUILD_WITH_LIBDL
fork_LDADD += -ldl
fork2_LDADD += -ldl
endif
if LTTNG_TOOLS_BUILD_WITH_LIBC_DL
fork_LDADD += -lc
fork2_LDADD += -lc
endif

noinst_SCRIPTS = test_fork test_fork.py
EXTRA_DIST = test_fork test_fork.py
