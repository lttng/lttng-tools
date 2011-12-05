ACLOCAL_AMFLAGS = -I config

SUBDIRS = benchmark \
		  liblttng-sessiond-comm \
		  libkernelctl \
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

bench:
	./benchmark/runall.sh
