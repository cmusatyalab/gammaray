bin_PROGRAMS       += bin/gray-ndb-queuer \
					  bin/gray-inferencer
noinst_LTLIBRARIES += lib/libqemucommon.la\
					  lib/libredis.la 

lib_libredis_la_SOURCES = src/gray-inferencer/redis_queue.c
lib_libredis_la_LIBADD  = $(libdir)/libbitarray.la \
						  $(libdir)/libutil.la
lib_libredis_la_CFLAGS  = $(AM_CFLAGS) \
						  -I/usr/include/hiredis

lib_libqemucommon_la_SOURCES = src/gray-inferencer/deep_inspection.c \
							   src/gray-inferencer/qemu_common.c
lib_libqemucommon_la_LIBADD  = $(libdir)/libbson.la \
							   $(libdir)/libext4.la \
							   $(libdir)/libntfs.la

bin_gray_ndb_queuer_SOURCES = src/gray-inferencer/gray-ndb-queuer.c
bin_gray_ndb_queuer_LDADD   = $(libdir)/libbitarray.la \
							  $(libdir)/libcolor.la \
							  $(libdir)/libqemucommon.la \
							  $(libdir)/libredis.la \
							  $(libdir)/libutil.la \
							  -lpthread

bin_gray_inferencer_SOURCES = src//gray-inferencer/gray-inferencer.c
bin_gray_inferencer_LDADD   = $(libdir)/libbitarray.la \
							  $(libdir)/libcolor.la \
							  $(libdir)/libext4.la \
							  $(libdir)/libntfs.la \
							  $(libdir)/libqemucommon.la \
							  $(libdir)/libredis.la \
							  $(libdir)/libutil.la \
							  -lpthread
