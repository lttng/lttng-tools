SUBDIRS = . tools kernel

AM_CFLAGS = -g -Wall
AM_LDFLAGS = -lurcu -lurcu-cds

EXTRA_DIST = run-report.py test_list.py runall.sh

if HAVE_LIBLTTNG_UST_CTL
SUBDIRS += ust
endif # HAVE_LIBLTTNG_UST_CTL

check-am:
	./runall.sh
