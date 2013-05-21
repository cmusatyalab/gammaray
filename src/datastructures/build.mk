check_PROGRAMS		+= bin/test/bitarray-test
noinst_LTLIBRARIES 	+= lib/libbitarray.la

lib_libbitarray_la_SOURCES = src/datastructures/bitarray.c
lib_libbitarray_la_LIBADD  = $(libdir)/libcolor.la \
							 $(libdir)/libutil.la

bin_test_bitarray_test_SOURCES = src/datastructures/bitarray-test.c
bin_test_bitarray_test_LDADD   = $(libdir)/libbitarray.la \
							  	 $(libdir)/libcolor.la \
								 $(libdir)/libutil.la
