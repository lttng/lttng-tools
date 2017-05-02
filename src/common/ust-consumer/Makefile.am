if HAVE_LIBLTTNG_UST_CTL

noinst_LTLIBRARIES = libust-consumer.la

libust_consumer_la_SOURCES = ust-consumer.c ust-consumer.h

libust_consumer_la_LIBADD = \
			-llttng-ust-ctl \
			$(top_builddir)/src/common/relayd/librelayd.la

endif
