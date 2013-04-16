bin_test_PROGRAMS  += bin/test/bson_test
bin_tools_PROGRAMS += bin/tools/bson_printer
noinst_LTLIBRARIES += lib/libbson.la

lib_libbson_la_SOURCES = src/bson/bson-encoder.c \
						 src/bson/bson-decoder.c \
						 src/bson/bson-util.c
lib_libbson_la_LIBADD = $(libdir)/libcolor.la $(libdir)/libutil.la

bin_tools_bson_printer_SOURCES = src/bson/bson_printer.c
bin_tools_bson_printer_LDADD = $(libdir)/libbson.la $(libdir)/libcolor.la

bin_test_bson_test_SOURCES = src/bson/bson_test.c
bin_test_bson_test_LDADD = $(libdir)/libbson.la
