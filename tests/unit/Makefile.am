SUBDIRS = ini_config

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils/ -I$(srcdir)

LOG_DRIVER_FLAGS='--merge'
LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_srcdir)/config/tap-driver.sh

TESTS = test_kernel_data \
	test_session \
	test_uri \
	test_utils_parse_size_suffix \
	test_utils_expand_path \
	test_string_utils \
	test_notification \
	ini_config/test_ini_config

LIBTAP=$(top_builddir)/tests/utils/tap/libtap.la

LIBCOMMON=$(top_builddir)/src/common/libcommon.la
LIBSTRINGUTILS=$(top_builddir)/src/common/string-utils/libstring-utils.la
LIBSESSIOND_COMM=$(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la
LIBHASHTABLE=$(top_builddir)/src/common/hashtable/libhashtable.la
LIBRELAYD=$(top_builddir)/src/common/relayd/librelayd.la
LIBLTTNG_CTL=$(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la

# Define test programs
noinst_PROGRAMS = test_uri test_session test_kernel_data
noinst_PROGRAMS += test_utils_parse_size_suffix test_utils_expand_path
noinst_PROGRAMS += test_string_utils test_notification

if HAVE_LIBLTTNG_UST_CTL
noinst_PROGRAMS += test_ust_data
TESTS += test_ust_data
endif

# URI unit tests
test_uri_SOURCES = test_uri.c
test_uri_LDADD = $(LIBTAP) $(LIBCOMMON) $(LIBHASHTABLE) $(DL_LIBS)

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
		     $(LIBHASHTABLE) $(DL_LIBS) -lrt
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
		   $(top_builddir)/src/bin/lttng-sessiond/notification-thread-commands.$(OBJEXT) \
		   $(top_builddir)/src/common/libcommon.la \
		   $(top_builddir)/src/common/health/libhealth.la \
		   $(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la

test_ust_data_SOURCES = test_ust_data.c
test_ust_data_LDADD = $(LIBTAP) $(LIBCOMMON) $(LIBRELAYD) $(LIBSESSIOND_COMM)\
		      $(LIBHASHTABLE) $(DL_LIBS) -lrt -llttng-ust-ctl
test_ust_data_LDADD += $(UST_DATA_TRACE)
endif

# Kernel data structures unit test
KERN_DATA_TRACE=$(top_builddir)/src/bin/lttng-sessiond/trace-kernel.$(OBJEXT) \
		$(top_builddir)/src/bin/lttng-sessiond/consumer.$(OBJEXT) \
		$(top_builddir)/src/bin/lttng-sessiond/utils.$(OBJEXT) \
		$(top_builddir)/src/common/libcommon.la \
		$(top_builddir)/src/common/health/libhealth.la \
		$(top_builddir)/src/bin/lttng-sessiond/notification-thread-commands.$(OBJEXT) \
		$(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la

test_kernel_data_SOURCES = test_kernel_data.c
test_kernel_data_LDADD = $(LIBTAP) $(LIBCOMMON) $(LIBRELAYD) $(LIBSESSIOND_COMM) \
			 $(LIBHASHTABLE) $(DL_LIBS) -lrt
test_kernel_data_LDADD += $(KERN_DATA_TRACE)

# utils suffix for unit test
UTILS_SUFFIX=$(top_builddir)/src/common/libcommon.la

# parse_size_suffix unit test
test_utils_parse_size_suffix_SOURCES = test_utils_parse_size_suffix.c
test_utils_parse_size_suffix_LDADD = $(LIBTAP) $(LIBHASHTABLE) $(LIBCOMMON) $(DL_LIBS)
test_utils_parse_size_suffix_LDADD += $(UTILS_SUFFIX)

# expand_path unit test
test_utils_expand_path_SOURCES = test_utils_expand_path.c
test_utils_expand_path_LDADD = $(LIBTAP) $(LIBHASHTABLE) $(LIBCOMMON) $(DL_LIBS)
test_utils_expand_path_LDADD += $(UTILS_SUFFIX)

# string utilities unit test
test_string_utils_SOURCES = test_string_utils.c
test_string_utils_LDADD = $(LIBTAP) $(LIBCOMMON) $(LIBSTRINGUTILS) $(DL_LIBS)

# Notification api
test_notification_SOURCES = test_notification.c
test_notification_LDADD = $(LIBTAP) $(LIBLTTNG_CTL) $(DL_LIBS)
