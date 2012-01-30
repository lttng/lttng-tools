AM_CFLAGS = -I. -O2
AM_LDFLAGS = -llttng-ust -ldl

noinst_PROGRAMS = gen-nevents
gen_nevents_SOURCES = gen-nevents.c tp.c ust_gen_nevents.h
gen_nevents_LDADD = -llttng-ust

noinst_SCRIPTS = run
EXTRA_DIST = run
