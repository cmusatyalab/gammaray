bin_PROGRAMS += bin/gray_fs

bin_gray_fs_SOURCES = src/inference_engine/async_queuer.c
bin_gray_fs_LDADD = $(libdir)/libbitarray.la $(libdir)/libcolor.la \
						 $(libdir)/libredis.la $(libdir)/libutil.la \
						 $(libdir)/libqemucommon.la -lpthread
