# SPDX-License-Identifier: GPL-2.0-only

if HAVE_LIBLTTNG_UST_CTL
SUBDIRS = \
	before-after \
	blocking \
	buffers-pid \
	clock-override \
	daemon \
	exit-fast \
	fork \
	getcpu-override \
	high-throughput \
	java-jul \
	java-log4j \
	java-log4j2 \
	libc-wrapper \
	linking \
	low-throughput \
	multi-lib \
	multi-session \
	namespaces \
	nprocesses \
	overlap \
	periodical-metadata-flush \
	rotation-destroy-flush \
	type-declarations \
	ust-constructor

if HAVE_OBJCOPY
SUBDIRS += \
	baddr-statedump \
	ust-dl
endif

EXTRA_DIST = \
	test_event_basic \
	test_event_perf	\
	test_event_tracef

all-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			cp -f $(srcdir)/$$script $(builddir); \
		done; \
	fi

clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			rm -f $(builddir)/$$script; \
		done; \
	fi

endif
