bin_test_PROGRAMS  += bin/test/bitarray_test
noinst_LTLIBRARIES += lib/libbitarray.la

bitarraysrc = $(srcdir)/src/datastructures

lib_libbitarray_la_SOURCES = $(bitarraysrc)/bitarray.c
lib_libbitarray_la_LIBADD = $(libdir)/libcolor.la $(libdir)/libutil.la

bin_test_bitarray_test_SOURCES = $(bitarraysrc)/bitarray_test.c
bin_test_bitarray_test_LDADD = $(libdir)/libutil.la $(libdir)/libcolor.la \
							   $(libdir)/libbitarray.la
