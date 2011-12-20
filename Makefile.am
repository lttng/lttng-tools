ACLOCAL_AMFLAGS = -I config

SUBDIRS = liblttng-sessiond-comm \
		  libkernelctl \
		  librunas \
		  liblttng-kconsumer \
		  liblttng-ustconsumer \
		  liblttng-consumer \
		  lttng-consumerd

if ! BUILD_CONSUMERD_ONLY
SUBDIRS += liblttngctl \
           lttng \
           lttng-sessiond
endif

SUBDIRS += tests \
           include \
           doc
