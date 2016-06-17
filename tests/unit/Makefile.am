SUBDIRS = ini_config

AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src -I$(top_srcdir)/tests/utils/ -I$(srcdir)
AM_LDFLAGS =

LOG_DRIVER_FLAGS='--merge'
LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_srcdir)/config/tap-driver.sh

TESTS = test_kernel_data \
	test_session \
	test_uri \
	test_utils_parse_size_suffix \
	test_utils_expand_path \
	ini_config/test_ini_config

if LTTNG_TOOLS_BUILD_WITH_LIBDL
LIBS += -ldl
endif
if LTTNG_TOOLS_BUILD_WITH_LIBC_DL
LIBS += -lc
endif

LIBTAP=$(top_builddir)/tests/utils/tap/libtap.la

LIBCOMMON=$(top_builddir)/src/common/libcommon.la
LIBSESSIOND_COMM=$(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la
LIBHASHTABLE=$(top_builddir)/src/common/hashtable/libhashtable.la
LIBRELAYD=$(top_builddir)/src/common/relayd/librelayd.la

# Define test programs
noinst_PROGRAMS = test_uri test_session test_kernel_data
noinst_PROGRAMS += test_utils_parse_size_suffix test_utils_expand_path

if HAVE_LIBLTTNG_UST_CTL
noinst_PROGRAMS += test_ust_data
TESTS += test_ust_data
endif

# URI unit tests
test_uri_SOURCES = test_uri.c
test_uri_LDADD = $(LIBTAP) $(LIBCOMMON) $(LIBHASHTABLE)

# Session unit test
SESSIONS=$(top_builddir)/src/bin/lttng-sessiond/session.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/consumer.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/utils.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/snapshot.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/ht-cleanup.$(OBJEXT) \
	 $(top_builddir)/src/common/libcommon.la \
	 $(top_builddir)/src/common/testpoint/libtestpoint.la \
	 $(top_builddir)/src/common/compat/libcompat.la \
	 $(top_builddir)/src/common/health/libhealth.la \
	 $(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la


test_session_SOURCES = test_session.c
test_session_LDADD = $(LIBTAP) $(LIBCOMMON) $(LIBRELAYD) $(LIBSESSIOND_COMM) \
		     $(LIBHASHTABLE) -lrt
test_session_LDADD += $(SESSIONS)

# UST data structures unit test
if HAVE_LIBLTTNG_UST_CTL
UST_DATA_TRACE=$(top_builddir)/src/bin/lttng-sessiond/trace-ust.$(OBJEXT) \
	       $(top_builddir)/src/bin/lttng-sessiond/consumer.$(OBJEXT) \
	       $(top_builddir)/src/bin/lttng-sessiond/utils.$(OBJEXT) \
		   $(top_builddir)/src/bin/lttng-sessiond/buffer-registry.$(OBJEXT) \
		   $(top_builddir)/src/bin/lttng-sessiond/ust-registry.$(OBJEXT) \
		   $(top_builddir)/src/bin/lttng-sessiond/ust-metadata.$(OBJEXT) \
		   $(top_builddir)/src/bin/lttng-sessiond/ust-app.$(OBJEXT) \
		   $(top_builddir)/src/bin/lttng-sessiond/ust-consumer.$(OBJEXT) \
		   $(top_builddir)/src/bin/lttng-sessiond/fd-limit.$(OBJEXT) \
		   $(top_builddir)/src/bin/lttng-sessiond/session.$(OBJEXT) \
		   $(top_builddir)/src/bin/lttng-sessiond/snapshot.$(OBJEXT) \
		   $(top_builddir)/src/bin/lttng-sessiond/agent.$(OBJEXT) \
		   $(top_builddir)/src/common/libcommon.la \
		   $(top_builddir)/src/common/health/libhealth.la \
		   $(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la

test_ust_data_SOURCES = test_ust_data.c
test_ust_data_LDADD = $(LIBTAP) $(LIBCOMMON) $(LIBRELAYD) $(LIBSESSIOND_COMM)\
		      $(LIBHASHTABLE) -lrt -llttng-ust-ctl
test_ust_data_LDADD += $(UST_DATA_TRACE)
endif

# Kernel data structures unit test
KERN_DATA_TRACE=$(top_builddir)/src/bin/lttng-sessiond/trace-kernel.$(OBJEXT) \
		$(top_builddir)/src/bin/lttng-sessiond/consumer.$(OBJEXT) \
		$(top_builddir)/src/bin/lttng-sessiond/utils.$(OBJEXT) \
		$(top_builddir)/src/common/libcommon.la \
		$(top_builddir)/src/common/health/libhealth.la \
		$(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la

test_kernel_data_SOURCES = test_kernel_data.c
test_kernel_data_LDADD = $(LIBTAP) $(LIBCOMMON) $(LIBRELAYD) $(LIBSESSIOND_COMM) \
			 $(LIBHASHTABLE) -lrt
test_kernel_data_LDADD += $(KERN_DATA_TRACE)

# utils suffix for unit test
UTILS_SUFFIX=$(top_builddir)/src/common/libcommon.la

# parse_size_suffix unit test
test_utils_parse_size_suffix_SOURCES = test_utils_parse_size_suffix.c
test_utils_parse_size_suffix_LDADD = $(LIBTAP) $(LIBHASHTABLE) $(LIBCOMMON)
test_utils_parse_size_suffix_LDADD += $(UTILS_SUFFIX)

# expand_path unit test
test_utils_expand_path_SOURCES = test_utils_expand_path.c
test_utils_expand_path_LDADD = $(LIBTAP) $(LIBHASHTABLE) $(LIBCOMMON)
test_utils_expand_path_LDADD += $(UTILS_SUFFIX)
