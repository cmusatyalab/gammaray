noinst_LTLIBRARIES += lib/libredis.la lib/libqemucommon.la

bin_PROGRAMS += bin/async_queuer bin/inference_engine

lib_libredis_la_SOURCES = src/inference_engine/redis_queue.c
lib_libredis_la_LIBADD = $(libdir)/libbitarray.la $(libdir)/libutil.la
lib_libredis_la_CFLAGS = $(AM_CFLAGS) -I/usr/include/hiredis

lib_libqemucommon_la_SOURCES = src/inference_engine/qemu_common.c \
							   src/inference_engine/deep_inspection.c
lib_libqemucommon_la_LIBADD = $(libdir)/libbson.la

bin_async_queuer_SOURCES = src/inference_engine/async_queuer.c
bin_async_queuer_LDADD = $(libdir)/libbitarray.la $(libdir)/libcolor.la \
						 $(libdir)/libredis.la $(libdir)/libutil.la \
						 $(libdir)/libqemucommon.la -lpthread

bin_inference_engine_SOURCES = src/inference_engine/inference_engine.c
bin_inference_engine_LDADD = $(libdir)/libbitarray.la $(libdir)/libcolor.la \
							 $(libdir)/libredis.la $(libdir)/libutil.la \
							 $(libdir)/libqemucommon.la $(libdir)/libext4.la \
							 $(libdir)/libntfs.la -lpthread
