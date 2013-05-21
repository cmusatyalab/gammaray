check_PROGRAMS 		 += bin/tools/bson-printer
check_PROGRAMS 		 += bin/test/bson-test
noinst_LTLIBRARIES 	 += lib/libbson.la

lib_libbson_la_SOURCES = src/bson/bson-encoder.c \
						 src/bson/bson-decoder.c \
						 src/bson/bson-util.c
lib_libbson_la_LIBADD  = $(libdir)/libcolor.la \
						 $(libdir)/libutil.la

bin_tools_bson_printer_SOURCES = src/bson/bson-printer.c
bin_tools_bson_printer_LDADD   = $(libdir)/libbson.la \
							     $(libdir)/libcolor.la

bin_test_bson_test_SOURCES = src/bson/bson-test.c
bin_test_bson_test_LDADD   = $(libdir)/libbson.la
