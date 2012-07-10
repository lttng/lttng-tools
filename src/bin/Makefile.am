ACLOCAL_AMFLAGS = -I config

SUBDIRS = lttng-consumerd

if ! BUILD_CONSUMERD_ONLY
SUBDIRS += lttng \
           lttng-sessiond \
           lttng-relayd
endif
