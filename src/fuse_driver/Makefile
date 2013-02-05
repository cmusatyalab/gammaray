default:
	@clang -Wall \
		   -Werror \
		   xray_fs.c \
		   ../stream_analyzer/redis_queue.c \
		   ../stream_analyzer/deep_inspection.c \
		   ../disk_analyzer/ext4/ext4.c \
		   ../util/color.c \
		   ../util/util.c \
		   ../bson/bson-encoder.c \
		   ../bson/bson-decoder.c \
		   -o xray_fs \
		   -lhiredis \
		   -I../disk_analyzer/ext4 \
		   -I../disk_analyzer/ext2 \
		   -I../disk_analyzer/mbr \
		   -I../util \
		   -I../bson \
		   -I../stream_analyzer \
		   -I/usr/include/hiredis \
		   `pkg-config fuse --cflags --libs`

test: default
	@mkdir -p /tmp/test
	@./xray_fs -s -d /tmp/test /home/wolf/VM/vm_ext4_test/vm_ext4_test.raw
	@ls test
	@sleep 0.25
	@sudo umount /tmp/test
	@rm -rf /tmp/test

clean:
	@rm -rf /tmp/test
	@rm xray_fs
	@sudo umount /tmp/test

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
