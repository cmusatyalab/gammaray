bin_PROGRAMS += bin/gray_fs

bin_gray_fs_SOURCES = src/inference_engine/async_queuer.c
bin_gray_fs_LDADD   = $(libdir)/libbitarray.la \
					  $(libdir)/libcolor.la \
					  $(libdir)/libqemucommon.la \
					  $(libdir)/libredis.la \
					  $(libdir)/libutil.la \
					  -lpthread
