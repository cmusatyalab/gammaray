#setup 
ACLOCAL_AMFLAGS = -I build-aux/m4
AM_CFLAGS = -I$(srcdir)/src/include

# distribution
#EXTRA_DIST = libperf.h perf_event.h libperf_example.c libperf_test.c libperf_benchmark.c

# helper libraries
noinst_LTLIBRARIES = libbitarray.la libbson.la libcolor.la libutil.la

libcolor_la_SOURCES = src/util/color.c
libutil_la_SOURCES = src/util/util.c
libbitarray_la_SOURCES = src/datastructures/bitarray.c
libbitarray_la_LIBADD = libcolor.la libutil.la
libbson_la_SOURCES = src/bson/bson-encoder.c \
					 src/bson/bson-decoder.c \
					 src/bson/bson-util.c
libbson_la_LIBADD = libcolor.la libutil.la

# binaries
bin_PROGRAMS = bitarray_test bson_printer bson_test
bindir = $(srcdir)/bin

bitarray_test_SOURCES = src/datastructures/bitarray_test.c
bitarray_test_LDADD = libutil.la libcolor.la libbitarray.la

bson_printer_SOURCES = src/bson/bson_printer.c
bson_printer_LDADD = libbson.la libcolor.la

bson_test_SOURCES = src/bson/bson_test.c
bson_test_LDADD = libbson.la
