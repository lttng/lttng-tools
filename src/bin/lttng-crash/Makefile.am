AM_CPPFLAGS += -DINSTALL_BIN_PATH=\""$(bindir)"\"

if EMBED_HELP
AM_CPPFLAGS += -I$(top_builddir)/doc/man
endif

bin_PROGRAMS = lttng-crash

lttng_crash_SOURCES = lttng-crash.c

lttng_crash_LDADD = $(top_builddir)/src/common/libcommon.la \
			$(top_builddir)/src/common/config/libconfig.la
