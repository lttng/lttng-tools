AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src -I$(top_srcdir)/tests/utils/ -I$(srcdir)
AM_LDFLAGS =

if LTTNG_TOOLS_BUILD_WITH_LIBDL
AM_LDFLAGS += -ldl
endif
if LTTNG_TOOLS_BUILD_WITH_LIBC_DL
AM_LDFLAGS += -lc
endif

LIBCOMMON=$(top_builddir)/src/common/libcommon.la
LIBSESSIOND_COMM=$(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la
LIBHASHTABLE=$(top_builddir)/src/common/hashtable/libhashtable.la

EXTRA_DIST = run.sh

if HAVE_LIBLTTNG_UST_CTL
noinst_PROGRAMS = test_uri test_session test_ust_data test_kernel_data
else
noinst_PROGRAMS = test_uri test_session	test_kernel_data
endif

# URI unit tests
test_uri_SOURCES = test_uri.c
test_uri_LDADD = $(LIBCOMMON)

# Session unit test
SESSIONS=$(top_srcdir)/src/bin/lttng-sessiond/session.c 	\
	 $(top_srcdir)/src/bin/lttng-sessiond/consumer.c 	\
	 $(top_srcdir)/src/common/uri.c 			\
	 $(top_srcdir)/src/common/utils.c 			\
	 $(top_srcdir)/src/common/error.c

test_session_SOURCES = test_session.c $(SESSIONS)
test_session_LDADD = $(LIBCOMMON) $(LIBSESSIOND_COMM) $(LIBHASHTABLE)

# UST data structures unit test
if HAVE_LIBLTTNG_UST_CTL
UST_DATA_TRACE=$(top_srcdir)/src/bin/lttng-sessiond/trace-ust.c \
	       $(top_srcdir)/src/bin/lttng-sessiond/consumer.c	\
	       $(top_srcdir)/src/common/uri.c			\
	       $(top_srcdir)/src/common/utils.c

test_ust_data_SOURCES = test_ust_data.c $(UST_DATA_TRACE)
test_ust_data_LDADD = $(LIBCOMMON) $(LIBSESSIOND_COMM) $(LIBHASHTABLE)
endif

# Kernel data structures unit test
KERN_DATA_TRACE=$(top_srcdir)/src/bin/lttng-sessiond/trace-kernel.c 	\
		$(top_srcdir)/src/bin/lttng-sessiond/consumer.c 	\
		$(top_srcdir)/src/common/uri.c 				\
		$(top_srcdir)/src/common/utils.c

test_kernel_data_SOURCES = test_kernel_data.c $(KERN_DATA_TRACE)
test_kernel_data_LDADD = $(LIBCOMMON) $(LIBSESSIOND_COMM) $(LIBHASHTABLE)
