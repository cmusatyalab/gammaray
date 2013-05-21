check_PROGRAMS 		+= bin/test/color-test \
					   bin/test/util-test
noinst_LTLIBRARIES 	+= lib/libcolor.la \
					   lib/libutil.la

lib_libcolor_la_SOURCES = src/util/color.c
lib_libutil_la_SOURCES  = src/util/util.c

bin_test_color_test_SOURCES = src/util/color-test.c
bin_test_color_test_LDADD   = $(libdir)/libcolor.la

bin_test_util_test_SOURCES = src/util/util-test.c
bin_test_util_test_LDADD   = $(libdir)/libutil.la
