check_PROGRAMS 		+= bin/test/nbd-test \
					   bin/test/nbd-queuer-test
noinst_LTLIBRARIES 	+= lib/libnbd.la

lib_libnbd_la_SOURCES = src/nbd/nbd.c
lib_libnbd_la_LIBADD  = $(libdir)/libcolor.la \
					    $(libdir)/libutil.la \
						-levent
lib_libnbd_la_CFLAGS  = $(AM_CFLAGS) \
						-I/usr/include/hiredis

bin_test_nbd_test_SOURCES = src/nbd/nbd-test.c
bin_test_nbd_test_LDADD   = $(libdir)/libnbd.la \
							-lhiredis

bin_test_nbd_queuer_test_SOURCES = src/nbd/nbd-queuer-test.c 
bin_test_nbd_queuer_test_LDADD   = $(libdir)/libnbd.la
