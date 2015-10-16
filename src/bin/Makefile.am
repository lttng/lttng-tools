ACLOCAL_AMFLAGS = -I config

SUBDIRS =

# Make sure to always distribute all folders
# since SUBDIRS is decided at configure time.
DIST_SUBDIRS = lttng-consumerd lttng lttng-sessiond lttng-relayd \
	       lttng-crash

if BUILD_BIN_LTTNG
SUBDIRS += lttng
endif

if BUILD_BIN_LTTNG_CONSUMERD
SUBDIRS += lttng-consumerd
endif

if BUILD_BIN_LTTNG_CRASH
SUBDIRS += lttng-crash
endif

if BUILD_BIN_LTTNG_RELAYD
SUBDIRS += lttng-relayd
endif

if BUILD_BIN_LTTNG_SESSIOND
SUBDIRS += lttng-sessiond
endif
