check_PROGRAMS 		+= bin/test/nbd-test
noinst_LTLIBRARIES 	+= lib/libnbd.la

lib_libnbd_la_SOURCES = src/nbd/nbd.c
lib_libnbd_la_LIBADD  = $(libdir)/libcolor.la \
					    $(libdir)/libutil.la \
						-levent

bin_test_nbd_test_SOURCES = src/nbd/nbd-test.c
bin_test_nbd_test_LDADD   = $(libdir)/libnbd.la
