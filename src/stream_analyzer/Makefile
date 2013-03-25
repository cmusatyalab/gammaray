default:
	@clang async_queuer.c -g \
		 qemu_common.c \
		 ../util/color.c \
		 ../util/util.c \
		 ../datastructures/bitarray.c \
		 ../bson/bson-encoder.c \
		 ../bson/bson-decoder.c \
		 ../disk_analyzer/ext2/ext2.c \
		 ../datastructures/bst.c \
		 ../datastructures/linkedlist.c \
		 ../disk_analyzer/ext4/ext4.c \
		 ../disk_analyzer/ntfs/ntfs.c \
		 deep_inspection.c \
		 redis_queue.c \
		 -lhiredis \
		 -lrt \
		 -pthread \
		 -o async_queuer \
		 -Wall \
		 -Werror \
		 -I../util \
		 -I/usr/include/hiredis \
		 -I../datastructures \
		 -I../bson \
		 -I../disk_analyzer/ext2 \
		 -I../disk_analyzer/ext4 \
		 -I../disk_analyzer/ntfs\
		 -I../disk_analyzer/mbr \
		 -g \
		 -lm \
		 #-DNOCOLOR

	@clang inference_engine.c -g \
		 qemu_common.c \
		 ../util/color.c \
		 ../util/util.c \
		 ../datastructures/bitarray.c \
		 ../bson/bson-encoder.c \
		 ../bson/bson-decoder.c \
		 ../disk_analyzer/ext2/ext2.c \
		 ../datastructures/bst.c \
		 ../datastructures/linkedlist.c \
		 ../disk_analyzer/ext4/ext4.c \
		 ../disk_analyzer/ntfs/ntfs.c \
		 deep_inspection.c \
		 redis_queue.c \
		 -lhiredis \
		 -lrt \
		 -pthread \
		 -o inference_engine \
		 -Wall \
		 -Werror \
		 -I../disk_analyzer/ext2 \
		 -I../disk_analyzer/ext4 \
		 -I../disk_analyzer/ntfs\
		 -I../disk_analyzer/mbr \
		 -I../util \
		 -I../bson \
		 -I../datastructures \
		 -I/usr/include/hiredis \
		 -lm \
		 #-DNOCOLOR

	@clang inference_engine_ntfs.c -g \
		 qemu_common.c \
		 ../util/color.c \
		 ../util/util.c \
		 ../bson/bson-encoder.c \
		 ../bson/bson-decoder.c \
		 ../datastructures/bitarray.c \
		 ../disk_analyzer/ext2/ext2.c \
		 ../datastructures/bst.c \
		 ../datastructures/linkedlist.c \
		 ../disk_analyzer/ext4/ext4.c \
		 ../disk_analyzer/ntfs/ntfs.c \
		 deep_inspection.c \
		 redis_queue.c \
		 -lhiredis \
		 -lrt \
		 -pthread \
		 -o inference_engine_ntfs \
		 -Wall \
		 -Werror \
		 -I../disk_analyzer/ext2 \
		 -I../disk_analyzer/ext4 \
		 -I../disk_analyzer/ntfs\
		 -I../disk_analyzer/mbr \
		 -I../util \
		 -I../bson \
		 -I../datastructures \
		 -I/usr/include/hiredis \
		 -lm \
		 #-DNOCOLOR

test: clean default
	@redis-cli flushall
	./inference_engine \
		/home/wolf/Dropbox/Projects/xray/sample/ext4_index.bson \
	    4 \
		ext4_test_vm &
	sleep 20
	./async_queuer \
		/home/wolf/Dropbox/Projects/xray/sample/ext4_index.bson \
		/tmp/1GB_capture.bin \
	    4 &

test_ntfs: clean default
	@redis-cli flushall
	./inference_engine_ntfs \
		/tmp/win7enterprise.bson \
	    4 \
		ntfs_test_vm

test_async: clean default
	@redis-cli flushall
	@time ./async_queuer \
		/home/wolf/Dropbox/Projects/xray/sample/ext4_index.bson \
		/home/wolf/Dropbox/Projects/xray/sample/ext4_trace.bin \
	    4

test_async_mem: clean default
	@redis-cli flushall
	@valgrind --leak-check=full --show-reachable=yes time ./async_queuer \
		/home/wolf/Dropbox/Projects/xray/sample/ext4_index.bson \
		/home/wolf/Dropbox/Projects/xray/sample/ext4_trace.bin \
	    4

test_ext4: clean default
	@redis-cli flushall
	#@./async_queuer \
	#	/home/wolf/Dropbox/Projects/xray/sample/ext4_index.bson \
	#	/home/wolf/Dropbox/Projects/xray/sample/ext4_trace.bin \
	#    4
	@./inference_engine \
		/home/wolf/Dropbox/Projects/xray/sample/ext4_index.bson \
	    4 \
		ext4_test_vm

test_ext4_mem: clean default
	@redis-cli flushall
	@valgrind --leak-check=full --show-reachable=yes ./inference_engine \
		/home/wolf/Dropbox/Projects/xray/sample/ext4_index.bson \
	    4 \
		ext4_test_vm

gdb: default
	@gdb --args ./inference_engine \
		/tmp/tinycore.bson \
		/home/wolf/Dropbox/Projects/xray/sample/file_create_write_65k.log

memtest: default
	@valgrind --leak-check=full --show-reachable=yes ./inference_engine \
		/tmp/tinycore.bson \
		/home/wolf/Dropbox/Projects/xray/sample/file_create_write_65k.log \
		| less -R

clean:
	@rm -f inference_engine
	@rm -f inference_engine_ntfs
	@rm -f async_queuer
