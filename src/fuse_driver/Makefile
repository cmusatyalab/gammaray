default:
	@clang -Wall \
		   -Werror \
		   xray_unified_fs.c \
		   ../stream_analyzer/redis_queue.c \
		   ../stream_analyzer/deep_inspection.c \
		   ../disk_analyzer/ext4/ext4.c \
		   ../disk_analyzer/ntfs/ntfs.c \
		   ../util/color.c \
		   ../util/util.c \
		   ../bson/bson-encoder.c \
		   ../bson/bson-decoder.c \
		   ../datastructures/bitarray.c \
		   -g \
		   -o xray_unified_fs \
		   -lhiredis \
		   -I../disk_analyzer/ext4 \
		   -I../disk_analyzer/ext2 \
		   -I../disk_analyzer/ntfs \
		   -I../disk_analyzer/mbr \
		   -I../util \
		   -I../bson \
		   -I../datastructures \
		   -I../stream_analyzer \
		   -I/usr/include/hiredis \
		   `pkg-config fuse --cflags --libs` \
		   -lm

test_ntfs: default
	@mkdir -p /tmp/FUSE/test_ntfs
	@./xray_ntfs_fs -d -s -oallow_other /tmp/FUSE/test_ntfs /home/wolf/VM/vm_ntfs_test/win7enterprise.raw
	@sudo umount /tmp/test
	@rm -rf /tmp/test

test: default
	@mkdir -p /tmp/test
	@./xray_unified_fs -d -s /tmp/test /home/wolf/VM/vm_ext4_test/vm_ext4_test.raw
	@ls test
	@sleep 0.25
	#@sudo umount /tmp/test
	#@rm -rf /tmp/test

clean:
	@rm xray_unified_fs

hellofs:
	@clang -Wall \
		 -Werror \
		 hello_fs.c \
		 -o hello_fs \
		 `pkg-config fuse --cflags --libs`

test_hellofs: default
	@mkdir -p test
	@./hello_fs test
	@cat test/hello
	@sleep 0.25
	@sudo umount test
	@rm -rf test

clean_hellofs:
	@rm -rf test
	@rm hello_fs
	@sudo umount test
